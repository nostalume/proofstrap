package config

import (
	"fmt"
	"strconv"

	"github.com/nostalume/proofstrap/internal/model"
)

type resourceResult struct {
	resource model.Resource
	err      error
}

func result(resource model.Resource, err error) resourceResult {
	return resourceResult{resource: resource, err: err}
}

func admitPortable(origin string, raw rawTarget) (model.Graph, map[string]model.AccountKey, map[string]model.GroupKey, error) {
	accounts := make(map[string]model.AccountKey, len(raw.Accounts))
	groups := make(map[string]model.GroupKey, len(raw.Groups))
	if raw.Groups != nil && len(raw.Groups) == 0 {
		return model.Graph{}, nil, nil, diagnostic("InvalidValue", "groups", "explicit empty groups table")
	}
	if raw.Accounts != nil && len(raw.Accounts) == 0 {
		return model.Graph{}, nil, nil, diagnostic("InvalidValue", "accounts", "explicit empty accounts table")
	}
	if raw.Memberships != nil && len(raw.Memberships) == 0 {
		return model.Graph{}, nil, nil, diagnostic("InvalidValue", "memberships", "explicit empty memberships list")
	}
	provenance, err := model.NewProvenance(origin)
	if err != nil {
		return model.Graph{}, nil, nil, diagnostic("InvalidValue", "", err.Error())
	}
	var contributions []model.Contribution
	add := func(field string, built resourceResult) error {
		if built.err != nil {
			return diagnostic("InvalidValue", field, built.err.Error())
		}
		contribution, err := model.Contribute(built.resource, provenance)
		if err != nil {
			return diagnostic("InvalidValue", field, err.Error())
		}
		contributions = append(contributions, contribution)
		return nil
	}
	for _, name := range sortedKeys(raw.Groups) {
		key, err := model.NewGroupKey(name)
		if err != nil {
			return model.Graph{}, nil, nil, diagnostic("InvalidValue", "groups."+name, err.Error())
		}
		groups[name] = key
		item := raw.Groups[name]
		if item.GID == nil {
			err = add("groups."+name, result(model.NewExternalGroup(key)))
		} else {
			err = add("groups."+name, result(model.NewManagedGroup(key, *item.GID)))
		}
		if err != nil {
			return model.Graph{}, nil, nil, err
		}
	}
	for _, name := range sortedKeys(raw.Accounts) {
		key, err := model.NewAccountKey(name)
		if err != nil {
			return model.Graph{}, nil, nil, diagnostic("InvalidValue", "accounts."+name, err.Error())
		}
		accounts[name] = key
	}
	for _, name := range sortedKeys(raw.Accounts) {
		field, item, key := "accounts."+name, raw.Accounts[name], accounts[name]
		coordinates := 0
		if item.UID != nil {
			coordinates++
		}
		if item.Group != nil {
			coordinates++
		}
		if item.Home != nil {
			coordinates++
		}
		switch coordinates {
		case 0:
			err = add(field, result(model.NewExternalAccount(key)))
		case 3:
			group, exists := groups[*item.Group]
			if !exists {
				return model.Graph{}, nil, nil, diagnostic("MissingReference", field+".group", "group is not declared")
			}
			err = add(field, result(model.NewManagedAccount(key, *item.UID, group, *item.Home)))
		default:
			return model.Graph{}, nil, nil, diagnostic("InvalidValue", field, "uid, group, and home must be supplied together")
		}
		if err != nil {
			return model.Graph{}, nil, nil, err
		}
		if item.Mode != nil {
			if len(*item.Mode) != 4 {
				return model.Graph{}, nil, nil, diagnostic("InvalidValue", field+".mode", "mode must be four octal characters")
			}
			mode, parseErr := strconv.ParseUint(*item.Mode, 8, 16)
			if parseErr != nil {
				return model.Graph{}, nil, nil, diagnostic("InvalidValue", field+".mode", "mode must be an octal string")
			}
			if err = add(field+".home", result(model.NewHome(key))); err != nil {
				return model.Graph{}, nil, nil, err
			}
			if err = add(field+".mode", result(model.NewHomeMode(key, uint16(mode)))); err != nil {
				return model.Graph{}, nil, nil, err
			}
		}
		if item.Shell != nil {
			if err = add(field+".shell", result(model.NewAccountShell(key, *item.Shell))); err != nil {
				return model.Graph{}, nil, nil, err
			}
		}
		if item.Locked != nil {
			if !*item.Locked {
				return model.Graph{}, nil, nil, diagnostic("InvalidValue", field+".locked", "false unlock intent is not supported")
			}
			if err = add(field+".locked", result(model.NewAccountLock(key))); err != nil {
				return model.Graph{}, nil, nil, err
			}
		}
	}
	for index, item := range raw.Memberships {
		field := fmt.Sprintf("memberships[%d]", index)
		account, accountOK := accounts[item.Account]
		group, groupOK := groups[item.Group]
		if !accountOK {
			return model.Graph{}, nil, nil, diagnostic("MissingReference", field+".account", "account is not declared")
		}
		if !groupOK {
			return model.Graph{}, nil, nil, diagnostic("MissingReference", field+".group", "group is not declared")
		}
		if item.Present == nil {
			return model.Graph{}, nil, nil, diagnostic("InvalidValue", field+".present", "membership presence is required")
		}
		if err = add(field, result(model.NewMembership(account, group, *item.Present))); err != nil {
			return model.Graph{}, nil, nil, err
		}
	}
	if raw.Hostname != nil {
		if err = add("hostname", result(model.NewHostname(*raw.Hostname))); err != nil {
			return model.Graph{}, nil, nil, err
		}
	}
	if raw.Timezone != nil {
		if err = add("timezone", result(model.NewTimezone(*raw.Timezone))); err != nil {
			return model.Graph{}, nil, nil, err
		}
	}
	if len(contributions) > maxResources {
		return model.Graph{}, nil, nil, diagnostic("Limit", "", "portable resource limit exceeded")
	}
	graph, err := model.EmptyGraph().Add(contributions)
	if err != nil {
		return model.Graph{}, nil, nil, diagnostic("Conflict", "", err.Error())
	}
	edges := 0
	for _, node := range graph.Nodes() {
		edges += len(node.Dependencies())
	}
	if edges > maxEdges {
		return model.Graph{}, nil, nil, diagnostic("Limit", "", "portable dependency edge limit exceeded")
	}
	return graph, accounts, groups, nil
}

func validateProfileReferences(raw []rawProfile, accounts map[string]model.AccountKey, groups map[string]model.GroupKey) error {
	for index, item := range raw {
		for _, name := range sortedKeys(item.Arguments) {
			argument := item.Arguments[name]
			field := fmt.Sprintf("profiles[%d].arguments.%s", index, name)
			if argument.Account != nil {
				if _, ok := accounts[*argument.Account]; !ok {
					return diagnostic("MissingReference", field+".account", "account is not declared")
				}
			}
			if argument.Group != nil {
				if _, ok := groups[*argument.Group]; !ok {
					return diagnostic("MissingReference", field+".group", "group is not declared")
				}
			}
		}
	}
	return nil
}
