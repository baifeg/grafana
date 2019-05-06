package middleware

import (
	"encoding/base64"
	"strconv"
	"time"

	"github.com/grafana/grafana/pkg/log"
	"github.com/grafana/grafana/pkg/bus"
	m "github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/setting"
)

func HasValidToken(c *m.ReqContext) bool {
	tokens, ok := c.Req.URL.Query()["token"]
	if !ok || len(tokens) < 1 {
		token := c.GetCookie(setting.DcosTokenName)
		result, err := isTokenValid(token)
		if err != nil {
			return false
		}

		if result {
			initContextWithAnonymousUserByToken(c)
		}

		return result
	} else {
		token := string(tokens[0])
		result, err := isTokenValid(token)
		if err != nil {
			return false
		}

		if result {
			initContextWithAnonymousUserByToken(c)

			c.SetCookie(setting.DcosTokenName, token, 1800, setting.AppSubUrl+"/")
		}

		return result
	}
}

func isTokenValid(token string) (bool, error) {
	if len(token) == 0 {
		return false, nil
	}

	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		log.Error(2, "Decode token [%s] failed.", token)
		return false, err
	}
	tkSec, err2 := strconv.Atoi(string(data))
	if err2 != nil {
		return false, err2
	}
	nowSec := int(time.Now().Unix())

	if tkSec+1800 < nowSec || tkSec-1800 > nowSec {
		return false, nil
	}
	return true, nil
}

func initContextWithAnonymousUserByToken(ctx *m.ReqContext) bool {
	orgQuery := m.GetOrgByNameQuery{Name: setting.AnonymousOrgName}
	if err := bus.Dispatch(&orgQuery); err != nil {
		log.Error(3, "Anonymous access organization error: '%s': %s", setting.AnonymousOrgName, err)
		return false
	}

	ctx.IsSignedIn = false
	ctx.AllowAnonymous = true
	ctx.SignedInUser = &m.SignedInUser{IsAnonymous: true}
	ctx.OrgRole = m.RoleType(setting.AnonymousOrgRole)
	ctx.OrgId = orgQuery.Result.Id
	ctx.OrgName = orgQuery.Result.Name
	return true
}
