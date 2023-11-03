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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	eventv1 "github.com/fluxcd/pkg/apis/event/v1beta1"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/go-resty/resty/v2"
	giturls "github.com/whilp/git-urls"
)

// BitbucketServer is a notifier for BitBucket Server and Data Center.
type BitbucketServer struct {
	ProjectKey      string
	RepositorySlug  string
	ProviderUID     string
	ProviderAddress string
	Host            string
	Client          *resty.Client
}

const (
	BuildEndPoint             = "/rest/api/latest/projects/{projectKey}/repos/{repositorySlug}/commits/{commitId}/builds"
	GetBuildStatusQueryString = "key"
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

	bitbucketClient := resty.New()
	if len(token) == 0 && (len(username) == 0 || len(password) == 0) {
		return nil, errors.New("invalid credentials, expected to be one of username/password or API Token")
	}
	if len(token) > 0 {
		bitbucketClient.SetAuthToken(token)
	} else if len(username) > 0 && len(password) > 0 {
		bitbucketClient.SetBasicAuth(username, password)
	}

	bitbucketClient.SetHeader("x-atlassian-token", "no-check")
	bitbucketClient.SetHeader("x-requested-with", "XMLHttpRequest")
	if certPool != nil {
		bitbucketClient.SetTLSClientConfig(&tls.Config{
			RootCAs: certPool,
		})
	}

	return &BitbucketServer{
		ProjectKey:      projectkey,
		RepositorySlug:  reposlug,
		ProviderUID:     providerUID,
		Host:            hst,
		ProviderAddress: addr,
		Client:          bitbucketClient,
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

	dupe, err := checkDuplicateCommitStatus(ctx, b, rev, state, name, desc, id, key)
	if err != nil {
		return fmt.Errorf("could not get existing commit status: %v", err)
	}

	if dupe == false {
		_, err = postBuildStatus(ctx, b, rev, state, name, desc, id, key)
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

func checkDuplicateCommitStatus(ctx context.Context, b BitbucketServer, rev, state, name, desc, id, key string) (bool, error) {
	d, err := b.Client.R().
		SetContext(ctx).
		SetQueryParam(GetBuildStatusQueryString, key).
		Get(createApiPath(b, rev))
	if err != nil && d.StatusCode() != http.StatusNotFound {
		return false, err
	}

	if d.StatusCode() == http.StatusOK {
		var existingCommitStatus RestBuildStatus
		json.Unmarshal(d.Body(), &existingCommitStatus)
		// Do not post duplicate build status
		if existingCommitStatus.Key == key && existingCommitStatus.State == state && existingCommitStatus.Description == desc && existingCommitStatus.Name == name {
			return true, nil
		}
	}
	return false, nil
}

func postBuildStatus(ctx context.Context, b BitbucketServer, rev, state, name, desc, id, key string) (*resty.Response, error) {
	r, err := b.Client.R().
		SetContext(ctx).
		SetBody(RestBuildStatusSetRequest{
			Key:         key,
			State:       state,
			Url:         b.ProviderAddress,
			Description: desc,
			Name:        name,
		}).
		Post(createApiPath(b, rev))
	if err != nil {
		return r, err
	}

	return r, nil
}

func createApiPath(b BitbucketServer, rev string) string {
	// create path and map variables
	localVarPath := b.Host + BuildEndPoint
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
