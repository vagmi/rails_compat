package rails_compat

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDecodeRailsSessionShouldDecodeSession(t *testing.T) {

	keyBase := "f1d186616befd0912ed643cdc621377baa17368402970cfca9eaaf75f93286da121c22f1576ac5399a0d4c9ab3026849ebb67cd617437d73835c136e1c40a946"
	// this is the decrypted session content
	// {"session_id":"d8b8304f5f339a818e127aca2dfab742","user_return_to":"/","warden.user.user.key":[[4],"$2a$11$gZkXn2gGS11ROQQJ1./hGO"],"_csrf_token":"atHkScP0CWcPrcxIJtdPk2Yg1aKhPTQ5HYg+sP/rjts="}
	cookie := "bVdpR2NLeUhBTXFMUk5rdUMrUWtGTnlrWDhoNCtQZmFMRVVPUTJNQlhkR2VXOU9oME1vZ1NabHBqREFNbVAzYkVnWCtSUjRCaXJaZjBIbEFodXl6Y28yV0IxSmQ1bHgzOTJoNlZQQzN2TzZsSnNYbUgzWkFMb291Q3FRTWozVmc3elNxSi9LTUN6STA3dnk4bnRFZDRUUU94K2VteUIwNkUxdWF0Zk8wb2x3a3h4OWw1Q3BhYWhGTGZDSFJDdjdUL3lwRi9URVNMUEhVOGtSN3dPUHJuTkdKTzdyTnMzcDlaUHVxNzdQVTh4aHo1ZFVUWkJwdWY4M0tKZVE2THpMdzFiM1FEYU13dlh3dTZGOFMyWDF2UXc9PS0tU1l5ZjhrVnN3NTYyaWxnZkZMZFNIdz09"

	var sess map[string]interface{}

	decrypted := DecodeRailsSession(cookie, keyBase)
	buffer := bytes.NewBuffer([]byte(decrypted))
	decoder := json.NewDecoder(buffer)
	err := decoder.Decode(&sess)

	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	if sess["session_id"].(string) != "d8b8304f5f339a818e127aca2dfab742" {
		t.Logf("expected %s found %s\n", "d8b8304f5f339a818e127aca2dfab742", sess["session_id"].(string))
		t.FailNow()
	}
}

func TestExtractUserIdShouldExtractUserId(t *testing.T) {
	session := `{"session_id":"d8b8304f5f339a818e127aca2dfab742","user_return_to":"/","warden.user.user.key":[[42],"$2a$11$gZkXn2gGS11ROQQJ1./hGO"],"_csrf_token":"atHkScP0CWcPrcxIJtdPk2Yg1aKhPTQ5HYg+sP/rjts="}`
	uid, err := ExtractUserId(session)
	if err != nil {
		t.Log("expected no errors found error")
		t.Log(err)
		t.FailNow()
	}
	if uid != 42 {
		t.Logf("expected userID to be 42 found %d\n", uid)
		t.FailNow()
	}
}
func TestExtractUserIdShouldFailGraceFully(t *testing.T) {
	session := `{"session_id":"d8b8304f5f339a818e127aca2dfab742","user_return_to":"/","warden.user.user.key":[42,"$2a$11$gZkXn2gGS11ROQQJ1./hGO"],"_csrf_token":"atHkScP0CWcPrcxIJtdPk2Yg1aKhPTQ5HYg+sP/rjts="}`
	session2 := `{"session_id":"d8b8304f5f339a818e127aca2dfab742","user_return_to":"/","_csrf_token":"atHkScP0CWcPrcxIJtdPk2Yg1aKhPTQ5HYg+sP/rjts="}`
	expectFailure(session, t)
	expectFailure(session2, t)
}

func expectFailure(session string, t *testing.T) {
	uid, err := ExtractUserId(session)
	if err == nil {
		t.Log("expected error to be returned")
		t.FailNow()
	}
	if err.Error() != WARDEN_FORMAT_ERROR {
		t.Logf("expected to fail with %s found %v", WARDEN_FORMAT_ERROR, err.Error())
		t.FailNow()
	}
	if uid != -1 {
		t.Logf("UserID in case of error should be -1 found %d\n", uid)
		t.FailNow()
	}
}
