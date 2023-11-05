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
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"

	"net/http"
	"net/http/httptest"

	eventv1 "github.com/fluxcd/pkg/apis/event/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewBitbucketServerBasic(t *testing.T) {
	b, err := NewBitbucketServer("0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a", "https://example.com:7990/scm/projectfoo/repobar.git", "", nil, "dummyuser", "testpassword")
	assert.Nil(t, err)
	assert.Equal(t, b.Username, "dummyuser")
	assert.Equal(t, b.Password, "testpassword")
}

func TestNewBitbucketServerToken(t *testing.T) {
	b, err := NewBitbucketServer("0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a", "https://example.com:7990/scm/projectfoo/repobar.git", "BBDC-ODIxODYxMzIyNzUyOttorMjO059P2rYTb6EH7mP", nil, "", "")
	assert.Nil(t, err)
	assert.Equal(t, b.Token, "BBDC-ODIxODYxMzIyNzUyOttorMjO059P2rYTb6EH7mP")
}

func TestNewBitbucketServerInvalidCreds(t *testing.T) {
	_, err := NewBitbucketServer("0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a", "https://example.com:7990/scm/projectfoo/repobar.git", "", nil, "", "")
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "invalid credentials, expected to be one of username/password or API Token")
}

func TestNewBitbucketServerInvalidUrl(t *testing.T) {
	_, err := NewBitbucketServer("0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a", "ssh://git@example.com:7999/projectfoo/repobar.git", "BBDC-ODIxODYxMzIyNzUyOttorMjO059P2rYTb6EH7mP", nil, "", "")
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "Unsupported git scheme ssh in address \"ssh://git@example.com:7999/projectfoo/repobar.git\". Please provide address in http/https format for BitbucketServer provider")
}

func TestNewBitbucketServerInvalidRepo(t *testing.T) {
	_, err := NewBitbucketServer("0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a", "https://example.com:7990/scm/projectfoo/repobar/invalid.git", "BBDC-ODIxODYxMzIyNzUyOttorMjO059P2rYTb6EH7mP", nil, "", "")
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "invalid repository id \"projectfoo/repobar/invalid\"")
}

func TestPostBitbucketServerMissingRevision(t *testing.T) {
	b, err := NewBitbucketServer("0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a", "https://example.com:7990/scm/projectfoo/repobar.git", "BBDC-ODIxODYxMzIyNzUyOttorMjO059P2rYTb6EH7mP", nil, "", "")
	assert.Nil(t, err)

	//Validate missing revision
	err = b.Post(context.TODO(), generateTestEventKustomization("info", map[string]string{
		"dummybadrevision": "bad",
	}))
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "missing revision metadata")
}

func TestPostBitbucketServerBadCommitHash(t *testing.T) {
	b, err := NewBitbucketServer("0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a", "https://example.com:7990/scm/projectfoo/repobar.git", "BBDC-ODIxODYxMzIyNzUyOttorMjO059P2rYTb6EH7mP", nil, "", "")
	assert.Nil(t, err)

	//Validate extract commit hash
	err = b.Post(context.TODO(), generateTestEventKustomization("info", map[string]string{
		eventv1.MetaRevisionKey: "badhash",
	}))
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "Could not parse revision: failed to extract commit hash from 'badhash' revision")

}

func TestPostBitbucketServerBadBitbucketState(t *testing.T) {
	b, err := NewBitbucketServer("0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a", "https://example.com:7990/scm/projectfoo/repobar.git", "BBDC-ODIxODYxMzIyNzUyOttorMjO059P2rYTb6EH7mP", nil, "", "")
	assert.Nil(t, err)

	//Validate conversion to bitbucket state
	err = b.Post(context.TODO(), generateTestEventKustomization("badserveritystate", map[string]string{
		eventv1.MetaRevisionKey: "main@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
	}))
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "couldn't convert to bitbucket server state: Bitbucket server state generated on info or error events only")

}

func generateTestEventKustomization(severity string, metadata map[string]string) eventv1.Event {
	return eventv1.Event{
		InvolvedObject: corev1.ObjectReference{
			Kind:      "Kustomization",
			Namespace: "flux-system",
			Name:      "hello-world",
		},
		Severity:            severity,
		Timestamp:           metav1.Now(),
		Message:             "message",
		Reason:              "reason",
		Metadata:            metadata,
		ReportingController: "kustomize-controller",
		ReportingInstance:   "kustomize-controller-xyz",
	}
}

func TestBitBucketServerPostValidateRequest(t *testing.T) {
	tests := []struct {
		name        string
		headers     map[string]string
		username    string
		password    string
		token       string
		event       eventv1.Event
		provideruid string
		key         string
	}{
		{
			name:        "Validate Token Auth ",
			username:    "",
			password:    "",
			token:       "goodtoken",
			provideruid: "0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a",
			headers: map[string]string{
				"Authorization":     "Bearer goodtoken",
				"x-atlassian-token": "no-check",
				"x-requested-with":  "XMLHttpRequest",
			},
			event: generateTestEventKustomization("info", map[string]string{
				eventv1.MetaRevisionKey: "main@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
			}),
			key: sha1String(generateCommitStatusID("0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a", generateTestEventKustomization("info", map[string]string{
				eventv1.MetaRevisionKey: "main@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
			}))),
		},
		{
			name:        "Validate Basic Auth",
			username:    "hello",
			password:    "password",
			token:       "",
			provideruid: "0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a",
			headers: map[string]string{
				"Authorization":     "Basic " + base64.StdEncoding.EncodeToString([]byte("hello"+":"+"password")),
				"x-atlassian-token": "no-check",
				"x-requested-with":  "XMLHttpRequest",
			},
			event: generateTestEventKustomization("info", map[string]string{
				eventv1.MetaRevisionKey: "main@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
			}),
			key: sha1String(generateCommitStatusID("0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a", generateTestEventKustomization("info", map[string]string{
				eventv1.MetaRevisionKey: "main@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
			}))),
		},
		{
			name:        "Validate Post State=Successful",
			username:    "hello",
			password:    "password",
			token:       "",
			provideruid: "0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a",
			headers: map[string]string{
				"Authorization":     "Basic " + base64.StdEncoding.EncodeToString([]byte("hello"+":"+"password")),
				"x-atlassian-token": "no-check",
				"x-requested-with":  "XMLHttpRequest",
			},
			event: generateTestEventKustomization("info", map[string]string{
				eventv1.MetaRevisionKey: "main@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
			}),
			key: sha1String(generateCommitStatusID("0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a", generateTestEventKustomization("info", map[string]string{
				eventv1.MetaRevisionKey: "main@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
			}))),
		},
		{
			name:        "Validate Post State=Failed",
			username:    "hello",
			password:    "password",
			token:       "",
			provideruid: "0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a",
			headers: map[string]string{
				"Authorization":     "Basic " + base64.StdEncoding.EncodeToString([]byte("hello"+":"+"password")),
				"x-atlassian-token": "no-check",
				"x-requested-with":  "XMLHttpRequest",
			},
			event: generateTestEventKustomization("error", map[string]string{
				eventv1.MetaRevisionKey: "main@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
			}),
			key: sha1String(generateCommitStatusID("0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a", generateTestEventKustomization("error", map[string]string{
				eventv1.MetaRevisionKey: "main@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
			}))),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				// Validate Headers
				for key, value := range tt.headers {
					require.Equal(t, value, r.Header.Get(key))
				}

				// Validate URI
				require.Equal(t, r.URL.Path, "/rest/api/latest/projects/projectfoo/repos/repobar/commits/5394cb7f48332b2de7c17dd8b8384bbc84b7e738/builds")

				// Validate Get Build Status call
				if r.Method == http.MethodGet {

					//Validate that this GET request has a query string with "key" as the query paraneter
					require.Equal(t, r.URL.Query().Get(getBuildStatusQueryString), tt.key)

					// Validate that this GET request has no body
					require.Equal(t, http.NoBody, r.Body)
				}

				// Validate Post BuildStatus call
				if r.Method == http.MethodPost {

					// Validate that this POST request has no query string
					require.Equal(t, len(r.URL.Query()), 0)

					// Validate that this POST request has Content-Type: application/json header
					require.Equal(t, "application/json", r.Header.Get("Content-Type"))

					// Read json body of the request
					b, err := io.ReadAll(r.Body)
					require.NoError(t, err)

					// Parse json request into Payload Request body struct
					var payload RestBuildStatusSetRequest
					err = json.Unmarshal(b, &payload)
					require.NoError(t, err)

					// Validate Key
					require.Equal(t, payload.Key, tt.key)

					// Validate that state can be only SUCCESSFUL or FAILED
					if payload.State != "SUCCESSFUL" && payload.State != "FAILED" {
						require.Fail(t, "Invalid state")
					}

					// If severity of event is info, state should be SUCCESSFUL
					if tt.event.Severity == "info" {
						require.Equal(t, "SUCCESSFUL", payload.State)
					}

					// If severity of event is error, state should be FAILED
					if tt.event.Severity == "error" {
						require.Equal(t, "FAILED", payload.State)
					}

					// Validate description
					require.Equal(t, "reason", payload.Description)

					// Validate name(with description appended)
					require.Equal(t, "kustomization/hello-world"+" ["+payload.Description+"]", payload.Name)

					require.Contains(t, payload.Url, "/scm/projectfoo/repobar.git")

				}
			}))
			defer ts.Close()
			c, err := NewBitbucketServer(tt.provideruid, ts.URL+"/scm/projectfoo/repobar.git", tt.token, nil, tt.username, tt.password)
			require.NoError(t, err)
			err = c.Post(context.TODO(), tt.event)
			require.NoError(t, err)
		})
	}
}
