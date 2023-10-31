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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewBitbucketServerBasic(t *testing.T) {
	b, err := NewBitbucketServer("0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a", "https://example.com:7990/scm/projectfoo/repobar.git", "", nil, "dummyuser", "testpassword")
	assert.Nil(t, err)
	assert.Equal(t, b.Credentials.RestUsernamePasswordCredentials.Username, "dummyuser")
	assert.Equal(t, b.Credentials.RestUsernamePasswordCredentials.Password, "testpassword")
}

func TestNewBitbucketServerToken(t *testing.T) {
	b, err := NewBitbucketServer("0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a", "https://example.com:7990/scm/projectfoo/repobar.git", "BBDC-ODIxODYxMzIyNzUyOttorMjO059P2rYTb6EH7mP", nil, "", "")
	assert.Nil(t, err)
	assert.Equal(t, b.Credentials.RestBearerTokenCredentials.Token, "BBDC-ODIxODYxMzIyNzUyOttorMjO059P2rYTb6EH7mP")
}

func TestNewBitbucketServerInvalidCreds(t *testing.T) {
	_, err := NewBitbucketServer("0c9c2e41-d2f9-4f9b-9c41-bebc1984d67a", "https://example.com:7990/scm/projectfoo/repobar.git", "", nil, "", "")
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "invalid credentials, expected to be one of username,password or APIToken")
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
