/*
Copyright 2020 The Flux authors

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
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/antihax/optional"
	eventv1 "github.com/fluxcd/pkg/apis/event/v1beta1"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/gdasson/bitbucketv1go"
)

// Bitbucket is a Bitbucket Server notifier.
type BitbucketServer struct {
	ProjectKey      string
	RepositorySlug  string
	ProviderUID     string
	ProviderAddress string
	Credentials     *bitbucketv1go.Credentials
	Client          *bitbucketv1go.APIClient
}

// NewBitbucket creates and returns a new Bitbucket notifier.
func NewBitbucketServer(providerUID string, addr string, token string, certPool *x509.CertPool, username string, password string) (*BitbucketServer, error) {
	hst, id, err := parseBitbucketServerGitAddress(addr)
	if err != nil {
		return nil, err
	}

	c := &bitbucketv1go.Credentials{}
	if len(token) > 0 {
		c.RestBearerTokenCredentials.Token = token
	}
	if len(username) > 0 && len(password) > 0 {
		c.RestUsernamePasswordCredentials.Username = username
		c.RestUsernamePasswordCredentials.Password = password
	}
	if len(token) == 0 && (len(username) == 0 || len(password) == 0) {
		return nil, errors.New("invalid credentials, expected to be one of username,password or APIToken")
	}

	comp := strings.Split(id, "/")
	if len(comp) != 2 {
		return nil, fmt.Errorf("invalid repository id %q", id)
	}
	projectkey := comp[0]
	reposlug := comp[1]

	bitbucketConfig := bitbucketv1go.NewConfiguration()
	bitbucketConfig.BasePath = hst + "/rest"
	bitbucketConfig.AddDefaultHeader("x-atlassian-token", "no-check")
	bitbucketConfig.AddDefaultHeader("x-requested-with", "XMLHttpRequest")
	if certPool != nil {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		}
		hc := &http.Client{Transport: tr}
		bitbucketConfig.HTTPClient = hc
	}

	bitbucketClient := bitbucketv1go.NewAPIClient(bitbucketConfig)

	return &BitbucketServer{
		ProjectKey:      projectkey,
		RepositorySlug:  reposlug,
		ProviderUID:     providerUID,
		Credentials:     c,
		ProviderAddress: addr,
		Client:          bitbucketClient,
	}, nil
}

// Post Bitbucket build status
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
		return err
	}
	state, err := toBitbucketServerState(event.Severity)
	if err != nil {
		return err
	}

	name, desc := formatNameAndDescription(event)
	name = name + " [" + desc + "]" //Bitbucket server displays this data on browser. Thus adding description here.
	id := generateCommitStatusID(b.ProviderUID, event)
	// key has a limitation of 40 characters in bitbucket api
	key := sha1String(id)

	if len(b.Credentials.RestUsernamePasswordCredentials.Username) > 0 && len(b.Credentials.RestUsernamePasswordCredentials.Password) > 0 {
		ctx = context.WithValue(ctx, bitbucketv1go.ContextBasicAuth, bitbucketv1go.BasicAuth{
			UserName: b.Credentials.RestUsernamePasswordCredentials.Username,
			Password: b.Credentials.RestUsernamePasswordCredentials.Password,
		})
	}
	if len(b.Credentials.RestBearerTokenCredentials.Token) > 0 {
		ctx = context.WithValue(ctx, bitbucketv1go.ContextAccessToken, b.Credentials.RestBearerTokenCredentials.Token)
	}

	existingCommitStatus, httpResponse, err := b.Client.BuildsAndDeploymentsApi.Get(ctx, b.ProjectKey, rev, b.RepositorySlug,
		&bitbucketv1go.BuildsAndDeploymentsApiGetOpts{
			Key: optional.NewString(key),
		})
	if err != nil && httpResponse.StatusCode != 404 {
		return fmt.Errorf("could not get commit status: %v", err)
	}

	if httpResponse.StatusCode == 200 {
		// Do not post duplicate build status
		if existingCommitStatus.Key == key && existingCommitStatus.State == state && existingCommitStatus.Description == desc && existingCommitStatus.Name == name {
			return nil
		}
	}

	_, err = b.Client.BuildsAndDeploymentsApi.Add(ctx, b.ProjectKey, rev, b.RepositorySlug,
		&bitbucketv1go.BuildsAndDeploymentsApiAddOpts{
			Body: optional.NewInterface(bitbucketv1go.RestBuildStatusSetRequest{
				Key:         key,
				State:       state,
				Url:         b.ProviderAddress,
				Description: desc,
				Name:        name,
			})})
	if err != nil {
		return fmt.Errorf("could not post build status: %v", err)
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
		return "", errors.New("can't convert to bitbucket server state")
	}
}
