package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"strconv"
	"io"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/wbrefvem/go-bitbucket"
	"golang.org/x/oauth2"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/mattermost/mattermost/server/public/pluginapi"

	"github.com/mattermost/mattermost-plugin-bitbucket/server/templaterenderer"
	"github.com/mattermost/mattermost-plugin-bitbucket/server/webhook"
)

const (
	BitbucketTokenKey     = "_bitbuckettoken"
	BitbucketOauthKey     = "bitbucketoauthkey_"
	BitbucketAccountIDKey = "_bitbucketaccountid"

	BitbucketBaseURL = "https://bitbucket.org/"

	WsEventConnect    = "connect"
	WsEventDisconnect = "disconnect"
	WsEventRefresh    = "refresh"

	SettingButtonsTeam   = "team"
	SettingNotifications = "notifications"
	SettingReminders     = "reminders"
	SettingOn            = "on"
	SettingOff           = "off"
)

type Plugin struct {
	plugin.MattermostPlugin

	BotUserID string

	CommandHandlers map[string]commandHandleFunc

	// configurationLock synchronizes access to the configuration.
	configurationLock sync.RWMutex

	// configuration is the active plugin configuration. Consult getConfiguration and
	// setConfiguration for usage.
	configuration *Configuration

	// webhookHandler is responsible for handling webhook events.
	webhookHandler webhook.Webhook

	router *mux.Router
}

// NewPlugin returns an instance of a Plugin.
func NewPlugin() *Plugin {
	p := &Plugin{}

	p.CommandHandlers = map[string]commandHandleFunc{
		"subscriptions": p.handleSubscribe,
		"disconnect":    p.handleDisconnect,
		"todo":          p.handleTodo,
		"me":            p.handleMe,
		"help":          p.handleHelp,
		"":              p.handleHelp,
		"settings":      p.handleSettings,
		"diff":			 p.handleDiff,
	}

	return p
}

func (p *Plugin) initializeWebhookHandler() {
	templateRenderer := templaterenderer.MakeTemplateRenderer()
	templateRenderer.RegisterBitBucketAccountIDToUsernameMappingCallback(
		p.getBitBucketAccountIDToMattermostUsernameMapping)
	p.webhookHandler = webhook.NewWebhook(&subscriptionHandler{p}, &pullRequestReviewHandler{p}, templateRenderer)
}

func (p *Plugin) bitbucketConnect(token oauth2.Token) *bitbucket.APIClient {
	// get Oauth token source and client
	ts := p.getOAuthConfig().TokenSource(context.Background(), &token)

	// setup Oauth context
	auth := context.WithValue(context.Background(), bitbucket.ContextOAuth2, ts)

	tc := oauth2.NewClient(auth, ts)

	// create config for bitbucket API
	configBb := bitbucket.NewConfiguration()
	configBb.HTTPClient = tc

	// create new bitbucket client API
	return bitbucket.NewAPIClient(configBb)
}

func (p *Plugin) OnActivate() error {
	config := p.getConfiguration()

	if err := config.IsValid(); err != nil {
		return errors.Wrap(err, "invalid config")
	}

	if p.API.GetConfig().ServiceSettings.SiteURL == nil {
		return errors.New("siteURL is not set. Please set a siteURL and restart the plugin")
	}

	p.initializeAPI()
	p.initializeWebhookHandler()
	commands, err := p.getCommand()
	if err != nil {
		return errors.Wrap(err, "failed to register command")
	}

	err = p.API.RegisterCommand(commands)
	if err != nil {
		return errors.Wrap(err, "failed to register command")
	}

	client := pluginapi.NewClient(p.API, p.Driver)
	botID, err := client.Bot.EnsureBot(&model.Bot{
		Username:    "bitbucket",
		DisplayName: "BitBucket",
		Description: "Created by the BitBucket plugin.",
	})
	if err != nil {
		return errors.Wrap(err, "failed to ensure BitBucket bot")
	}

	p.BotUserID = botID

	bundlePath, err := p.API.GetBundlePath()
	if err != nil {
		return errors.Wrap(err, "couldn't get bundle path")
	}

	profileImage, err := os.ReadFile(filepath.Join(bundlePath, "assets", "profile.png"))
	if err != nil {
		return errors.Wrap(err, "couldn't read profile image")
	}

	appErr := p.API.SetProfileImage(botID, profileImage)
	if appErr != nil {
		return errors.Wrap(appErr, "couldn't set profile image")
	}

	return nil
}

func (p *Plugin) getOAuthConfig() *oauth2.Config {
	config := p.getConfiguration()

	authURL, _ := url.Parse(BitbucketBaseURL)
	tokenURL, _ := url.Parse(BitbucketBaseURL)
	authURL.Path = path.Join(authURL.Path, "site", "oauth2", "authorize")
	tokenURL.Path = path.Join(tokenURL.Path, "site", "oauth2", "access_token")

	return &oauth2.Config{
		ClientID:     config.BitbucketOAuthClientID,
		ClientSecret: config.BitbucketOAuthClientSecret,
		Scopes:       []string{"repository"},
		RedirectURL:  fmt.Sprintf("%s/plugins/%s/oauth/complete", *p.API.GetConfig().ServiceSettings.SiteURL, manifest.Id),
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL.String(),
			TokenURL: tokenURL.String(),
		},
	}
}

type BitbucketUserInfo struct {
	UserID             string
	Token              *oauth2.Token
	BitbucketUsername  string
	BitbucketAccountID string
	LastToDoPostAt     int64
	Settings           *UserSettings
}

type UserSettings struct {
	SidebarButtons string `json:"sidebar_buttons"`
	DailyReminder  bool   `json:"daily_reminder"`
	Notifications  bool   `json:"notifications"`
}

func (p *Plugin) storeBitbucketUserInfo(info *BitbucketUserInfo) error {
	config := p.getConfiguration()

	encryptedToken, err := encrypt([]byte(config.EncryptionKey), info.Token.AccessToken)
	if err != nil {
		return errors.Wrap(err, "error occurred while encrypting access token")
	}

	info.Token.AccessToken = encryptedToken

	jsonInfo, err := json.Marshal(info)
	if err != nil {
		return errors.Wrap(err, "error while converting user info to json")
	}

	if err := p.API.KVSet(info.UserID+BitbucketTokenKey, jsonInfo); err != nil {
		return errors.Wrap(err, "error occurred while trying to store user info into KV store")
	}

	return nil
}

func (p *Plugin) getBitbucketUserInfo(userID string) (*BitbucketUserInfo, *APIErrorResponse) {
	config := p.getConfiguration()

	var userInfo BitbucketUserInfo

	if infoBytes, err := p.API.KVGet(userID + BitbucketTokenKey); err != nil || infoBytes == nil {
		return nil, &APIErrorResponse{ID: APIErrorIDNotConnected, Message: "Must connect user account to Bitbucket first.", StatusCode: http.StatusBadRequest}
	} else if err := json.Unmarshal(infoBytes, &userInfo); err != nil {
		return nil, &APIErrorResponse{ID: "", Message: "Unable to parse token.", StatusCode: http.StatusInternalServerError}
	}

	unencryptedToken, err := decrypt([]byte(config.EncryptionKey), userInfo.Token.AccessToken)
	if err != nil {
		p.API.LogError("Unable to decrypt access token", "err", err.Error())
		return nil, &APIErrorResponse{ID: "", Message: "Unable to decrypt access token.", StatusCode: http.StatusInternalServerError}
	}

	userInfo.Token.AccessToken = unencryptedToken

	return &userInfo, nil
}

func (p *Plugin) storeBitbucketAccountIDToMattermostUserIDMapping(bitbucketAccountID, userID string) error {
	if err := p.API.KVSet(bitbucketAccountID+BitbucketAccountIDKey, []byte(userID)); err != nil {
		return errors.New("encountered error saving BitBucket account ID mapping")
	}
	return nil
}

func (p *Plugin) getBitbucketAccountIDToMattermostUserIDMapping(bitbucketAccountID string) string {
	userID, _ := p.API.KVGet(bitbucketAccountID + BitbucketAccountIDKey)
	return string(userID)
}

func (p *Plugin) disconnectBitbucketAccount(userID string) {
	userInfo, _ := p.getBitbucketUserInfo(userID)
	if userInfo == nil {
		return
	}

	if appErr := p.API.KVDelete(userID + BitbucketTokenKey); appErr != nil {
		p.API.LogWarn("Failed to delete bitbucket token from KV store", "userID", userID, "error", appErr.Error())
	}

	if appErr := p.API.KVDelete(userInfo.BitbucketAccountID + BitbucketAccountIDKey); appErr != nil {
		p.API.LogWarn("Failed to delete bitbucket account ID from KV store", "userID", userID,
			"userInfo.BitbucketAccountID", userInfo.BitbucketAccountID, "error", appErr.Error())
	}

	p.API.PublishWebSocketEvent(
		WsEventDisconnect,
		nil,
		&model.WebsocketBroadcast{UserId: userID},
	)
}

// CreateBotDMPost posts a direct message using the bot account.
// Any error are not returned and instead logged.
func (p *Plugin) CreateBotDMPost(userID, message, postType string) {
	channel, err := p.API.GetDirectChannel(userID, p.BotUserID)
	if err != nil {
		p.API.LogWarn("Couldn't get bot's DM channel", "userID", userID, "error", err.Error())
		return
	}

	post := &model.Post{
		UserId:    p.BotUserID,
		ChannelId: channel.Id,
		Message:   message,
		Type:      postType,
	}

	if _, err := p.API.CreatePost(post); err != nil {
		p.API.LogWarn("Failed to create DM post", "userID", userID, "error", err.Error())
		return
	}
}

func (p *Plugin) PostToDo(info *BitbucketUserInfo) {
	text, err := p.GetToDo(context.Background(), info, p.bitbucketConnect(*info.Token))
	if err != nil {
		p.API.LogWarn("Failed to get todo text", "userID", info.UserID, "error", err.Error())
		return
	}

	p.CreateBotDMPost(info.UserID, text, "custom_bitbucket_todo")
}

func (p *Plugin) GetToDo(ctx context.Context, userInfo *BitbucketUserInfo, bitbucketClient *bitbucket.APIClient) (string, error) {
	return "", nil

	// userRepos, err := p.getUserRepositories(ctx, bitbucketClient)
	// if err != nil {
	// 	return "", errors.Wrap(err, "error occurred while searching for repositories")
	// }

	// yourAssignments, err := p.getAssignedIssues(ctx, userInfo, bitbucketClient, userRepos)
	// if err != nil {
	// 	return "", errors.Wrap(err, "error occurred while searching for assignments")
	// }

	// yourOpenPrs, err := p.getOpenPRs(ctx, userInfo, bitbucketClient, userRepos)
	// if err != nil {
	// 	return "", errors.Wrap(err, "error occurred while searching for your open PRs")
	// }

	// assignedPRs, err := p.getAssignedPRs(ctx, userInfo, bitbucketClient, userRepos)
	// if err != nil {
	// 	return "", errors.Wrap(err, "error occurred while searching for assigned PRs")
	// }

	// text := "##### Your Assignments\n"

	// if len(yourAssignments) == 0 {
	// 	text += "You don't have any assignments.\n"
	// } else {
	// 	text += fmt.Sprintf("You have %v assignments:\n", len(yourAssignments))

	// 	for _, assign := range yourAssignments {
	// 		text += getToDoDisplayText(BitbucketBaseURL, assign.Title, assign.Links.Html.Href, "")
	// 	}
	// }

	// text += "##### Review Requests\n"

	// if len(assignedPRs) == 0 {
	// 	text += "You don't have any pull requests awaiting your review.\n"
	// } else {
	// 	text += fmt.Sprintf("You have %v pull requests awaiting your review:\n", len(assignedPRs))

	// 	for _, assign := range assignedPRs {
	// 		text += getToDoDisplayText(BitbucketBaseURL, assign.Title, assign.Links.Html.Href, "")
	// 	}
	// }

	// text += "##### Your Open Pull Requests\n"

	// if len(yourOpenPrs) == 0 {
	// 	text += "You don't have any open pull requests.\n"
	// } else {
	// 	text += fmt.Sprintf("You have %v open pull requests:\n", len(yourOpenPrs))

	// 	for _, assign := range yourOpenPrs {
	// 		text += getToDoDisplayText(BitbucketBaseURL, assign.Title, assign.Links.Html.Href, "")
	// 	}
	// }

	// return text, nil
}

func (p *Plugin) getUserRepositories(ctx context.Context, bitbucketClient *bitbucket.APIClient) ([]bitbucket.Repository, error) {
	options := make(map[string]interface{})
	options["role"] = "member"

	var urlForRepos string
	org := p.getConfiguration().BitbucketOrg
	if org != "" {
		urlForRepos = getYourOrgReposSearchQuery(org)
	} else {
		urlForRepos = getYourAllReposSearchQuery()
	}

	userRepos, err := p.fetchRepositoriesWithNextPagesIfAny(ctx, urlForRepos, bitbucketClient)
	if err != nil {
		return nil, errors.Wrap(err, "error occurred while fetching repositories")
	}

	return userRepos, nil
}

func (p *Plugin) fetchRepositoriesWithNextPagesIfAny(ctx context.Context, urlToFetch string, bitbucketClient *bitbucket.APIClient) ([]bitbucket.Repository, error) {
	var result []bitbucket.Repository

	paginatedRepositories, httpResponse, err := bitbucketClient.PagingApi.RepositoriesPageGet(ctx, urlToFetch)
	if err != nil {
		if httpResponse != nil {
			_ = httpResponse.Body.Close()
		}
		return nil, errors.Wrap(err, "error occurred while fetching repositories")
	}
	if httpResponse != nil {
		_ = httpResponse.Body.Close()
	}

	result = append(result, paginatedRepositories.Values...)

	if paginatedRepositories.Next != "" {
		nextPaginatedRepositories, err := p.fetchRepositoriesWithNextPagesIfAny(ctx, paginatedRepositories.Next, bitbucketClient)
		if err != nil {
			return nil, errors.Wrap(err, "error occurred while fetching repositories")
		}

		result = append(result, nextPaginatedRepositories...)
	}

	return result, nil
}

func (p *Plugin) getIssuesWithTerm(bitbucketClient *bitbucket.APIClient, searchTerm string) ([]bitbucket.Issue, error) {
	return []bitbucket.Issue{}, nil

	// userRepos, err := p.getUserRepositories(context.Background(), bitbucketClient)
	// if err != nil {
	// 	return nil, errors.Wrap(err, "error occurred while fetching repositories")
	// }

	// var foundIssues []bitbucket.Issue
	// for _, repo := range userRepos {
	// 	paginatedIssues, httpResponse, err := bitbucketClient.PagingApi.IssuesPageGet(context.Background(), getSearchIssuesQuery(repo.FullName, searchTerm))
	// 	if httpResponse != nil {
	// 		_ = httpResponse.Body.Close()
	// 	}
	// 	if err != nil {
	// 		return nil, errors.Wrap(err, "error occurred while fetching issues")
	// 	}

	// 	foundIssues = append(foundIssues, paginatedIssues.Values...)

	// 	if paginatedIssues.Next != "" {
	// 		for {
	// 			paginatedIssues, httpResponse, err = bitbucketClient.PagingApi.IssuesPageGet(context.Background(), paginatedIssues.Next)
	// 			if httpResponse != nil {
	// 				_ = httpResponse.Body.Close()
	// 			}
	// 			if err != nil {
	// 				return nil, errors.Wrap(err, "error occurred while fetching issues")
	// 			}

	// 			foundIssues = append(foundIssues, paginatedIssues.Values...)

	// 			if paginatedIssues.Next == "" {
	// 				break
	// 			}
	// 		}
	// 	}
	// }

	// return foundIssues, nil
}

func (p *Plugin) fetchIssuesWithNextPagesIfAny(ctx context.Context, urlToFetch string, bitbucketClient *bitbucket.APIClient) ([]bitbucket.Issue, error) {

	return []bitbucket.Issue{}, nil

	// var result []bitbucket.Issue

	// paginatedIssues, httpResponse, err := bitbucketClient.PagingApi.IssuesPageGet(ctx, urlToFetch)
	// if err != nil {
	// 	if httpResponse != nil {
	// 		_ = httpResponse.Body.Close()
	// 	}
	// 	return nil, errors.Wrap(err, "error occurred while fetching issues")
	// }

	// result = append(result, paginatedIssues.Values...)

	// if paginatedIssues.Next != "" {
	// 	for {
	// 		paginatedIssues, httpResponse, err = bitbucketClient.PagingApi.IssuesPageGet(context.Background(), paginatedIssues.Next)
	// 		if err != nil {
	// 			if httpResponse != nil {
	// 				_ = httpResponse.Body.Close()
	// 			}
	// 			return nil, errors.Wrap(err, "error occurred while fetching issues")
	// 		}

	// 		result = append(result, paginatedIssues.Values...)

	// 		if paginatedIssues.Next == "" {
	// 			break
	// 		}
	// 	}
	// }

	// return result, nil
}

func (p *Plugin) fetchPRsWithNextPagesIfAny(ctx context.Context, urlToFetch string, bitbucketClient *bitbucket.APIClient) ([]bitbucket.Pullrequest, error) {
	var result []bitbucket.Pullrequest

	paginatedPrs, httpResponse, err := bitbucketClient.PagingApi.PullrequestsPageGet(ctx, urlToFetch)
	if httpResponse != nil {
		_ = httpResponse.Body.Close()
	}
	if err != nil {
		return nil, errors.Wrap(err, "error occurred while fetching pull requests")
	}

	result = append(result, paginatedPrs.Values...)

	if paginatedPrs.Next != "" {
		for {
			paginatedPrs, httpResponse, err = bitbucketClient.PagingApi.PullrequestsPageGet(ctx, paginatedPrs.Next)
			if httpResponse != nil {
				_ = httpResponse.Body.Close()
			}
			if err != nil {
				return nil, errors.Wrap(err, "error occurred while fetching PRs")
			}

			result = append(result, paginatedPrs.Values...)

			if paginatedPrs.Next == "" {
				break
			}
		}
	}

	return result, nil
}

func (p *Plugin) getAssignedIssues(ctx context.Context, userInfo *BitbucketUserInfo, bitbucketClient *bitbucket.APIClient, userRepos []bitbucket.Repository) ([]bitbucket.Issue, error) {
	return []bitbucket.Issue{}, nil

	// var issuesResult []bitbucket.Issue

	// for _, repo := range userRepos {
	// 	urlForIssues := getYourAssigneeIssuesSearchQuery(userInfo.BitbucketAccountID, repo.FullName)

	// 	paginatedIssuesInRepo, err := p.fetchIssuesWithNextPagesIfAny(ctx, urlForIssues, bitbucketClient)
	// 	if err != nil {
	// 		p.API.LogWarn("Skipping repo due to issue fetch failure", "repo", repo.FullName, "error", err.Error())
	// 		continue // just skip this repo and continue with the rest
	// 		// OR return empty slice early:
	// 		// return []bitbucket.Issue{}, nil
	// 	}

	// 	issuesResult = append(issuesResult, paginatedIssuesInRepo...)
	// }

	// return issuesResult, nil
}

func (p *Plugin) getAssignedPRs(ctx context.Context, userInfo *BitbucketUserInfo, bitbucketClient *bitbucket.APIClient, userRepos []bitbucket.Repository) ([]bitbucket.Pullrequest, error) {
	var prsResult []bitbucket.Pullrequest
	for _, repo := range userRepos {
		urlForPRs := getYourAssigneePRsSearchQuery(userInfo.BitbucketAccountID, repo.FullName)

		paginatedIssuesInRepo, err := p.fetchPRsWithNextPagesIfAny(ctx, urlForPRs, bitbucketClient)
		if err != nil {
			return nil, errors.Wrap(err, "error occurred while fetching pull requests")
		}

		prsResult = append(prsResult, paginatedIssuesInRepo...)
	}

	return prsResult, nil
}

func (p *Plugin) getOpenPRs(ctx context.Context, userInfo *BitbucketUserInfo, bitbucketClient *bitbucket.APIClient, userRepos []bitbucket.Repository) ([]bitbucket.Pullrequest, error) {
	var prsResult []bitbucket.Pullrequest

	for _, repo := range userRepos {
		urlForPRs := getYourOpenPRsSearchQuery(userInfo.BitbucketAccountID, repo.FullName)

		paginatedIssuesInRepo, err := p.fetchPRsWithNextPagesIfAny(ctx, urlForPRs, bitbucketClient)
		if err != nil {
			return nil, errors.Wrap(err, "error occurred while fetching pull requests")
		}

		prsResult = append(prsResult, paginatedIssuesInRepo...)
	}

	return prsResult, nil
}

func (p *Plugin) checkOrg(org string) error {
	config := p.getConfiguration()

	configOrg := strings.TrimSpace(config.BitbucketOrg)
	if configOrg != "" && configOrg != org {
		return errors.Errorf("only repositories in the %v organization are supported", configOrg)
	}

	return nil
}

func (p *Plugin) sendRefreshEvent(userID string) {
	p.API.PublishWebSocketEvent(
		WsEventRefresh,
		nil,
		&model.WebsocketBroadcast{UserId: userID},
	)
}

func (p *Plugin) getBaseURL() string {
	return "https://bitbucket.org/"
}

// getBitBucketAccountIDToMattermostUsernameMapping maps a BitBucket account ID to the corresponding Mattermost username, if any.
func (p *Plugin) getBitBucketAccountIDToMattermostUsernameMapping(bitbucketAccountID string) string {
	user, _ := p.API.GetUser(p.getBitbucketAccountIDToMattermostUserIDMapping(bitbucketAccountID))
	if user == nil {
		return ""
	}

	return user.Username
}

func (p *Plugin) HasUnreads(info *BitbucketUserInfo) bool {
	return false

	// ctx := context.Background()
	// bitbucketClient := p.bitbucketConnect(*info.Token)

	// userRepos, err := p.getUserRepositories(ctx, bitbucketClient)
	// if err != nil {
	// 	p.API.LogError("error occurred while searching for repositories", "err", err.Error())
	// 	return false
	// }

	// yourAssignments, err := p.getAssignedIssues(ctx, info, bitbucketClient, userRepos)
	// if err != nil {
	// 	p.API.LogError("error occurred while searching for assignments", "err", err.Error())
	// 	return false
	// }
	// if len(yourAssignments) > 0 {
	// 	return true
	// }

	// yourOpenPrs, err := p.getOpenPRs(ctx, info, bitbucketClient, userRepos)
	// if err != nil {
	// 	p.API.LogError("error occurred while searching for your open PRs", "err", err.Error())
	// 	return false
	// }
	// if len(yourOpenPrs) > 0 {
	// 	return true
	// }

	// yourPrs, err := p.getAssignedPRs(ctx, info, bitbucketClient, userRepos)
	// if err != nil {
	// 	p.API.LogError("error occurred while searching for assigned PRs", "err", err.Error())
	// 	return false
	// }
	// if len(yourPrs) > 0 {
	// 	return true
	// }

	// return false
}

// getUsername returns the BitBucket username for a given Mattermost user,
// if the user is connected to BitBucket via this plugin.
// Otherwise it return the Mattermost username. It will be escaped via backticks.
func (p *Plugin) getUsername(mmUserID string) (string, error) {
	info, apiEr := p.getBitbucketUserInfo(mmUserID)
	if apiEr != nil {
		if apiEr.ID != APIErrorIDNotConnected {
			return "", apiEr
		}

		user, appEr := p.API.GetUser(mmUserID)
		if appEr != nil {
			return "", appEr
		}

		return fmt.Sprintf("`@%s`", user.Username), nil
	}

	return "@" + info.BitbucketUsername, nil
}

func (p *Plugin) handleDiff(c *plugin.Context, args *model.CommandArgs, parameters []string, info *bitbucketUserInfo) string {
	if len(parameters) != 2 {
		return "Usage: `/bitbucket diff owner/repo pr-number`"
	}

	repo := parameters[0]
	prNumStr := parameters[1]

	prNum, err := strconv.Atoi(prNumStr)
	if err != nil {
		return fmt.Sprintf("Invalid PR number: `%s`", prNumStr)
	}

	ownerRepo := strings.Split(repo, "/")
	if len(ownerRepo) != 2 {
		return "Repository must be in the format `owner/repo`"
	}
	owner, slug := ownerRepo[0], ownerRepo[1]

	diff, err := p.fetchPRDiff(owner, slug, prNum, info)
	if err != nil {
		return fmt.Sprintf("Error fetching diff: %v", err)
	}

	lines := strings.Split(diff, "\n")
	if len(lines) > 100 {
		lines = lines[:100]
	}
	preview := strings.Join(lines, "\n")

	fileID, uploadErr := p.uploadDiffFile(args, owner, slug, prNum, []byte(diff))
	if uploadErr != nil {
		return fmt.Sprintf("Error uploading diff file: %v", uploadErr)
	}

	link := p.getFileLink(fileID)

	return fmt.Sprintf(
		"Preview of PR `%s/%s#%d`\n```diff\n%s\n```\n@ai please review the code.\n[Download full diff](%s)",
		owner, slug, prNum, preview, link,
	)
}

func (p *Plugin) fetchPRDiff(owner, repo string, prID int, info *BitbucketUserInfo) (string, error) {
	url := fmt.Sprintf("https://api.bitbucket.org/2.0/repositories/%s/%s/pullrequests/%d/diff", owner, repo, prID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	// Adjust this based on your auth method
	req.Header.Set("Authorization", "Bearer "+info.OAuthToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Bitbucket API error: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (p *Plugin) uploadDiffFile(args *model.CommandArgs, owner, repo string, prID int, content []byte) (string, error) {
	fileName := fmt.Sprintf("%s-%s-pr%d.diff", owner, repo, prID)
	fileInfo, appErr := p.API.UploadFile(content, args.ChannelId, fileName)
	if appErr != nil {
		return "", appErr
	}
	return fileInfo.Id, nil
}

func (p *Plugin) getFileLink(fileID string) string {
	siteURL := *p.API.GetConfig().ServiceSettings.SiteURL
	return fmt.Sprintf("%s/files/%s", siteURL, fileID)
}