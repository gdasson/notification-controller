/*
Copyright 2023 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package notifier

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	eventv1 "github.com/fluxcd/pkg/apis/event/v1beta1"
	"github.com/fluxcd/pkg/apis/meta"
	giturls "github.com/whilp/git-urls"
)

// BitbucketServer is a notifier for BitBucket Server and Data Center.
type BitbucketServer struct {
	ProjectKey      string
	RepositorySlug  string
	ProviderUID     string
	ProviderAddress string
	Host            string
	Username        string
	Password        string
	Token           string
	Client          *http.Client
}

const (
	buildEndPoint             = "/rest/api/latest/projects/{projectKey}/repos/{repositorySlug}/commits/{commitId}/builds"
	getBuildStatusQueryString = "key"
	rqstTimeoutInSeconds      = 5
)

type RestBuildStatus struct {
	Name        string `json:"name,omitempty"`
	Key         string `json:"key,omitempty"`
	Parent      string `json:"parent,omitempty"`
	State       string `json:"state,omitempty"`
	Ref         string `json:"ref,omitempty"`
	BuildNumber string `json:"buildNumber,omitempty"`
	Description string `json:"description,omitempty"`
	Duration    int64  `json:"duration,omitempty"`
	UpdatedDate int64  `json:"updatedDate,omitempty"`
	CreatedDate int64  `json:"createdDate,omitempty"`
	Url         string `json:"url,omitempty"`
}

type RestBuildStatusSetRequest struct {
	BuildNumber string `json:"buildNumber,omitempty"`
	Description string `json:"description,omitempty"`
	Duration    int64  `json:"duration,omitempty"`
	Key         string `json:"key"`
	LastUpdated int64  `json:"lastUpdated,omitempty"`
	Name        string `json:"name,omitempty"`
	Parent      string `json:"parent,omitempty"`
	Ref         string `json:"ref,omitempty"`
	State       string `json:"state"`
	Url         string `json:"url"`
}

// NewBitbucketServer creates and returns a new NewBitbucketServer notifier.
func NewBitbucketServer(providerUID string, addr string, token string, certPool *x509.CertPool, username string, password string) (*BitbucketServer, error) {
	hst, id, err := parseBitbucketServerGitAddress(addr)
	if err != nil {
		return nil, err
	}

	comp := strings.Split(id, "/")
	if len(comp) != 2 {
		return nil, fmt.Errorf("invalid repository id %q", id)
	}
	projectkey := comp[0]
	reposlug := comp[1]

	httpClient := http.DefaultClient
	httpClient.Timeout = rqstTimeoutInSeconds * time.Second
	if certPool != nil {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		}
	}

	if len(token) == 0 && (len(username) == 0 || len(password) == 0) {
		return nil, errors.New("invalid credentials, expected to be one of username/password or API Token")
	}

	return &BitbucketServer{
		ProjectKey:      projectkey,
		RepositorySlug:  reposlug,
		ProviderUID:     providerUID,
		Host:            hst,
		ProviderAddress: addr,
		Token:           token,
		Username:        username,
		Password:        password,
		Client:          httpClient,
	}, nil
}

// Post Bitbucket Server build status
func (b BitbucketServer) Post(ctx context.Context, event eventv1.Event) error {
	// Skip progressing events
	if event.HasReason(meta.ProgressingReason) {
		return nil
	}
	revString, ok := event.Metadata[eventv1.MetaRevisionKey]
	if !ok {
		return errors.New("missing revision metadata")
	}
	rev, err := parseRevision(revString)
	if err != nil {
		return fmt.Errorf("Could not parse revision: %v", err)
	}
	state, err := toBitbucketServerState(event.Severity)
	if err != nil {
		return fmt.Errorf("couldn't convert to bitbucket server state: %v", err)
	}

	name, desc := formatNameAndDescription(event)
	name = name + " [" + desc + "]" //Bitbucket server displays this data on browser. Thus adding description here.
	id := generateCommitStatusID(b.ProviderUID, event)
	// key has a limitation of 40 characters in bitbucket api
	key := sha1String(id)

	u := createApiPath(b, rev)
	dupe, err := checkDuplicateCommitStatus(ctx, b, rev, state, name, desc, id, key, u)
	if err != nil {
		return fmt.Errorf("could not get existing commit status: %v", err)
	}

	if dupe == false {
		_, err = postBuildStatus(ctx, b, rev, state, name, desc, id, key, u)
		if err != nil {
			return fmt.Errorf("could not post build status: %v", err)
		}
	}

	return nil
}

func toBitbucketServerState(severity string) (string, error) {
	switch severity {
	case eventv1.EventSeverityInfo:
		return "SUCCESSFUL", nil
	case eventv1.EventSeverityError:
		return "FAILED", nil
	default:
		return "", errors.New("Bitbucket server state generated on info or error events only")
	}
}

func checkDuplicateCommitStatus(ctx context.Context, b BitbucketServer, rev, state, name, desc, id, key, u string) (bool, error) {
	// Prepare request object
	req, err := prepareCommonRequest(ctx, u, nil, http.MethodGet, b, key, rev)
	if err != nil {
		return false, fmt.Errorf("Could not check duplicate commit status: %v", err)
	}

	// Set query string
	q := url.Values{}
	q.Add(getBuildStatusQueryString, key)
	req.URL.RawQuery = q.Encode()

	// Make a GET call
	d, err := b.Client.Do(req)
	if err != nil && d.StatusCode != http.StatusNotFound {
		return false, fmt.Errorf("Failed API call to check duplicate commit status: %v", err)
	}
	defer d.Body.Close()

	if d.StatusCode == http.StatusOK {
		bd, err := io.ReadAll(d.Body)
		if err != nil {
			return false, fmt.Errorf("Could not read response body for duplicate commit status: %v", err)
		}
		var existingCommitStatus RestBuildStatus
		json.Unmarshal(bd, &existingCommitStatus)
		// Do not post duplicate build status
		if existingCommitStatus.Key == key && existingCommitStatus.State == state && existingCommitStatus.Description == desc && existingCommitStatus.Name == name {
			return true, nil
		}
	}
	return false, nil
}

func postBuildStatus(ctx context.Context, b BitbucketServer, rev, state, name, desc, id, key, url string) (*http.Response, error) {
	//Prepare json body
	j := &RestBuildStatusSetRequest{
		Key:         key,
		State:       state,
		Url:         b.ProviderAddress,
		Description: desc,
		Name:        name,
	}
	p := new(bytes.Buffer)
	json.NewEncoder(p).Encode(j)

	//Prepare request
	req, err := prepareCommonRequest(ctx, url, p, http.MethodPost, b, key, rev)
	if err != nil {
		return nil, fmt.Errorf("Could not post Build commit status: %v", err)
	}

	// Add Content type header
	req.Header.Add("Content-Type", "application/json")

	// Make a POST call
	resp, err := b.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Could not post Build commit status: %v", err)
	}
	defer resp.Body.Close()
	return resp, nil
}

func createApiPath(b BitbucketServer, rev string) string {
	localVarPath := b.Host + buildEndPoint
	localVarPath = strings.Replace(localVarPath, "{"+"projectKey"+"}", fmt.Sprintf("%v", b.ProjectKey), -1)
	localVarPath = strings.Replace(localVarPath, "{"+"commitId"+"}", fmt.Sprintf("%v", rev), -1)
	localVarPath = strings.Replace(localVarPath, "{"+"repositorySlug"+"}", fmt.Sprintf("%v", b.RepositorySlug), -1)
	return localVarPath
}

func parseBitbucketServerGitAddress(s string) (string, string, error) {
	u, err := giturls.Parse(s)
	if err != nil {
		return "", "", fmt.Errorf("failed parsing URL %q: %w", s, err)
	}

	scheme := u.Scheme
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", fmt.Errorf("Unsupported git scheme %s in address %q. Please provide address in http/https format for BitbucketServer provider", u.Scheme, s)
	}

	id := strings.TrimPrefix(u.Path, "/scm/") //https://community.atlassian.com/t5/Bitbucket-questions/remote-url-in-Bitbucket-server-what-does-scm-represent-is-it/qaq-p/2060987
	id = strings.TrimSuffix(id, ".git")
	host := fmt.Sprintf("%s://%s", scheme, u.Host)
	return host, id, nil
}

func prepareCommonRequest(ctx context.Context, path string, body io.Reader, method string, b BitbucketServer, key, rev string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, path, body)
	if err != nil {
		return nil, fmt.Errorf("Could not prepare request: %v", err)
	}

	if b.Token != "" {
		req.Header.Add("Authorization", "Bearer "+b.Token)
	} else {
		req.SetBasicAuth(b.Username, b.Password)
	}
	req.Header.Add("x-atlassian-token", "no-check")
	req.Header.Add("x-requested-with", "XMLHttpRequest")

	return req, nil
}
