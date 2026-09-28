#!/usr/bin/env bash
# Shared validation helpers. This file defines functions only.

validation_error() {
    printf 'ERROR: %s\n' "$*" >&2
    return 1
}

validate_hostname() {
    local value="$1"
    [[ ${#value} -le 253 ]] || return 1
    [[ "$value" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]]
}

validate_host_label() {
    local value="$1"
    [[ ${#value} -le 63 ]] || return 1
    [[ "$value" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]
}

sites_records() {
    local registry="$1"
    sed -e 's/[[:space:]]*$//' -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$registry"
}

validate_sites_file() {
    local registry="$1"
    local line line_number=0 domain port tuning
    local -A domains=()

    [[ -r "$registry" ]] || validation_error "cannot read sites registry: $registry" || return 1

    while IFS= read -r line || [[ -n "$line" ]]; do
        line_number=$((line_number + 1))
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]] && continue

        if [[ ! "$line" =~ ^([^:[:space:]]+):([0-9]{1,5})(:(standard|streaming))?[[:space:]]*$ ]]; then
            validation_error "$registry:$line_number: expected domain:port[:standard|streaming]"
            return 1
        fi
        domain="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
        tuning="${BASH_REMATCH[4]:-standard}"

        validate_hostname "$domain" ||
            { validation_error "$registry:$line_number: invalid lowercase DNS hostname: $domain"; return 1; }
        (( 10#$port >= 1 && 10#$port <= 65535 )) ||
            { validation_error "$registry:$line_number: port must be 1-65535"; return 1; }
        [[ "$tuning" == "standard" || "$tuning" == "streaming" ]] ||
            { validation_error "$registry:$line_number: unsupported tuning: $tuning"; return 1; }
        [[ -z "${domains[$domain]:-}" ]] ||
            { validation_error "$registry:$line_number: duplicate domain: $domain"; return 1; }
        domains["$domain"]=1
    done < "$registry"

    (( ${#domains[@]} > 0 )) ||
        { validation_error "$registry must contain at least one site"; return 1; }
}

# Succeeds when one `ufw show added` line opens SSH to any source address.
# Rules scoped to tailscale0 or to specific source addresses are not public.
ufw_rule_is_public_ssh() {
    local rule="$1" source ports port
    local -a port_list

    rule="${rule%% comment *}"
    [[ "$rule" =~ ^ufw\ (allow|limit)\  ]] || return 1
    [[ "$rule" =~ \ on\ tailscale0( |$) ]] && return 1

    if [[ "$rule" =~ \ from\ ([^ ]+) ]]; then
        source="${BASH_REMATCH[1]}"
        [[ "$source" == "any" || "$source" == "0.0.0.0/0" || "$source" == "::/0" ]] || return 1
    fi

    # Simple syntax: ufw allow [in] 22[/tcp] | OpenSSH | ssh
    [[ "$rule" =~ ^ufw\ (allow|limit)(\ in)?\ (22|22/tcp|OpenSSH|ssh)$ ]] && return 0

    # Full syntax: ... to <addr> app OpenSSH | to <addr> port <list> [proto tcp]
    [[ "$rule" =~ \ to\ [^\ ]+\ app\ (OpenSSH|ssh)( |$) ]] && return 0
    [[ "$rule" =~ \ proto\ udp( |$) ]] && return 1
    if [[ "$rule" =~ \ to\ [^\ ]+\ port\ ([0-9,:]+) ]]; then
        ports="${BASH_REMATCH[1]}"
        IFS=',' read -r -a port_list <<< "$ports"
        for port in "${port_list[@]}"; do
            if [[ "$port" == *:* ]]; then
                (( 10#${port%%:*} <= 22 && 22 <= 10#${port##*:} )) && return 0
            else
                (( 10#$port == 22 )) && return 0
            fi
        done
    fi
    return 1
}

validate_runtime_config() {
    local required country

    for required in BACKEND_TAILNET_HOST ALLOWED_COUNTRY CERTBOT_EMAIL; do
        [[ -n "${!required:-}" ]] ||
            { validation_error "$required is not set in $CONFIG_FILE"; return 1; }
    done

    validate_hostname "$BACKEND_TAILNET_HOST" ||
        { validation_error "BACKEND_TAILNET_HOST is not a valid lowercase DNS hostname"; return 1; }

    for country in $ALLOWED_COUNTRY; do
        [[ "$country" =~ ^[A-Z]{2}$ ]] ||
            { validation_error "ALLOWED_COUNTRY must contain uppercase two-letter codes"; return 1; }
    done

    [[ "$CERTBOT_EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] ||
        { validation_error "CERTBOT_EMAIL is not a valid email address"; return 1; }

    [[ "${SWAP_SIZE_MB:-2048}" =~ ^[1-9][0-9]*$ ]] ||
        { validation_error "SWAP_SIZE_MB must be a positive integer"; return 1; }

    [[ "${HSTS_MAX_AGE:-31536000}" =~ ^(0|[1-9][0-9]{0,8})$ ]] ||
        { validation_error "HSTS_MAX_AGE must be a whole number of seconds (0 disables HSTS)"; return 1; }

    [[ "${LOCK_ROOT_PASSWORD:-false}" == "true" || "${LOCK_ROOT_PASSWORD:-false}" == "false" ]] ||
        { validation_error "LOCK_ROOT_PASSWORD must be true or false"; return 1; }

    if [[ "${LOCK_ROOT_PASSWORD:-false}" == "true" && -z "${NEW_SUDO_USERNAME:-}" ]]; then
        validation_error "LOCK_ROOT_PASSWORD=true requires NEW_SUDO_USERNAME"
        return 1
    fi

    if [[ -n "${NEW_SUDO_USERNAME:-}" && ! "$NEW_SUDO_USERNAME" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        validation_error "NEW_SUDO_USERNAME contains unsupported characters"
        return 1
    fi

    if [[ -n "${VPS_HOSTNAME:-}" ]] &&
       ! validate_hostname "$VPS_HOSTNAME" &&
       ! validate_host_label "$VPS_HOSTNAME"; then
        validation_error "VPS_HOSTNAME is not a valid lowercase hostname"
        return 1
    fi

    if [[ -n "${MAXMIND_ACCOUNT_ID:-}" || -n "${MAXMIND_LICENSE_KEY:-}" ]]; then
        [[ -n "${MAXMIND_ACCOUNT_ID:-}" && -n "${MAXMIND_LICENSE_KEY:-}" ]] ||
            { validation_error "set both MaxMind values or neither"; return 1; }
    fi

    local url_var
    for url_var in HEALTHCHECKS_PING_URL UPGRADE_HEALTHCHECKS_PING_URL; do
        if [[ -n "${!url_var:-}" && ! "${!url_var}" =~ ^https?://[^[:space:]]+$ ]]; then
            validation_error "$url_var must be an http(s):// URL with no whitespace"
            return 1
        fi
    done

    if [[ -n "${HEALTHCHECK_DOMAIN:-}" ]] && ! validate_hostname "$HEALTHCHECK_DOMAIN"; then
        validation_error "HEALTHCHECK_DOMAIN is not a valid lowercase DNS hostname"
        return 1
    fi
    if [[ -n "${HEALTHCHECK_PATH:-}" &&
          ( "${HEALTHCHECK_PATH:0:1}" != "/" || "$HEALTHCHECK_PATH" =~ [[:space:]] ) ]]; then
        validation_error "HEALTHCHECK_PATH must begin with / and contain no whitespace"
        return 1
    fi
    if [[ -n "${HEALTHCHECK_EXPECTED_STATUS:-}" &&
          ! "$HEALTHCHECK_EXPECTED_STATUS" =~ ^[1-5][0-9][0-9](,[1-5][0-9][0-9])*$ ]]; then
        validation_error "HEALTHCHECK_EXPECTED_STATUS must be a comma-separated HTTP status list"
        return 1
    fi
}
