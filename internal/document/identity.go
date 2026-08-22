package document

import (
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

func admitIdentity(origin string, raw rawDocument) (model.Graph, map[string]model.AccountKey, map[string]model.GroupKey, error) {
	accounts := make(map[string]model.AccountKey, len(raw.Accounts))
	groups := make(map[string]model.GroupKey, len(raw.Groups))
	if raw.Groups != nil && len(raw.Groups) == 0 {
		return model.Graph{}, nil, nil, diagnostic("InvalidValue", "groups", "explicit empty groups table")
	}
	if raw.Accounts != nil && len(raw.Accounts) == 0 {
		return model.Graph{}, nil, nil, diagnostic("InvalidValue", "accounts", "explicit empty accounts table")
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
		if name == "root" {
			return model.Graph{}, nil, nil, diagnostic("InvalidValue", "groups."+name, "root group is outside config authority")
		}
		key, err := model.NewGroupKey(name)
		if err != nil {
			return model.Graph{}, nil, nil, diagnostic("InvalidValue", "groups."+name, err.Error())
		}
		groups[name] = key
		item := raw.Groups[name]
		if item.GID == nil {
			err = add("groups."+name, result(model.NewExternalGroup(key)))
		} else {
			if *item.GID == 0 {
				return model.Graph{}, nil, nil, diagnostic("InvalidValue", "groups."+name+".gid", "GID zero is outside config authority")
			}
			err = add("groups."+name, result(model.NewManagedGroup(key, *item.GID)))
		}
		if err != nil {
			return model.Graph{}, nil, nil, err
		}
	}
	for _, name := range sortedKeys(raw.Accounts) {
		if name == "root" {
			return model.Graph{}, nil, nil, diagnostic("InvalidValue", "accounts."+name, "root account is outside config authority")
		}
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
			if *item.UID == 0 {
				return model.Graph{}, nil, nil, diagnostic("InvalidValue", field+".uid", "UID zero is outside config authority")
			}
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
		if item.HomeMode != nil {
			if len(*item.HomeMode) != 4 {
				return model.Graph{}, nil, nil, diagnostic("InvalidValue", field+".home_mode", "mode must be four octal characters")
			}
			mode, parseErr := strconv.ParseUint(*item.HomeMode, 8, 16)
			if parseErr != nil {
				return model.Graph{}, nil, nil, diagnostic("InvalidValue", field+".home_mode", "mode must be an octal string")
			}
			if err = add(field+".home", result(model.NewHome(key))); err != nil {
				return model.Graph{}, nil, nil, err
			}
			if err = add(field+".home_mode", result(model.NewHomeMode(key, uint16(mode)))); err != nil {
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
	for _, name := range sortedKeys(raw.Accounts) {
		item, account := raw.Accounts[name], accounts[name]
		field := "accounts." + name + ".supplementary"
		if item.Supplementary != nil && len(item.Supplementary) == 0 {
			return model.Graph{}, nil, nil, diagnostic("InvalidValue", field, "explicit empty supplementary table")
		}
		for _, groupName := range sortedKeys(item.Supplementary) {
			group, ok := groups[groupName]
			if !ok {
				return model.Graph{}, nil, nil, diagnostic("MissingReference", field+"."+groupName, "group is not declared")
			}
			if item.Group != nil && *item.Group == groupName {
				return model.Graph{}, nil, nil, diagnostic("InvalidValue", field+"."+groupName, "primary group cannot be supplementary")
			}
			if err = add(field+"."+groupName, result(model.NewMembership(account, group, item.Supplementary[groupName]))); err != nil {
				return model.Graph{}, nil, nil, err
			}
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
