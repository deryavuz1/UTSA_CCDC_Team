#!/usr/bin/env bash
# modules/04_generate.sh — Generate passwords and SSH keypairs
# Reads selections, generates passwords for 'random' selections,
# generates ED25519 keypairs for all non-skip users.
# Entry point: generate_main

GEN_DIR="${SESSION_DIR}/gen"

generate_main() {
    header "Generating Passwords & SSH Keys"
    echo
    mkdir -p "$GEN_DIR" "${SESSION_DIR}/sshkeys"

    local count_pass=0 count_key=0 count_skip=0

    while IFS= read -r uid; do
        local sel_file="${SESSION_DIR}/selections/${uid}.sel"
        local sel; sel=$(cat "$sel_file" 2>/dev/null || echo "pending")

        case "$sel" in
            skip)
                info "  ${uid}: SKIP"
                ((count_skip++)) || true
                continue
                ;;
            pending)
                warn "  ${uid}: PENDING (treating as skip)"
                printf 'skip' > "$sel_file"
                ((count_skip++)) || true
                continue
                ;;
            random)
                local newpass; newpass=$(gen_random_password)
                printf '%s' "$newpass" > "${GEN_DIR}/${uid}.pass"
                # Update sel to record the actual password
                printf 'random:%s' "$newpass" > "$sel_file"
                info "  ${uid}: generated password"
                ((count_pass++)) || true
                ;;
            random:*)
                # Already generated in a prior run
                local newpass="${sel#random:}"
                printf '%s' "$newpass" > "${GEN_DIR}/${uid}.pass"
                info "  ${uid}: using previously generated password"
                ((count_pass++)) || true
                ;;
            set:*)
                local newpass="${sel#set:}"
                printf '%s' "$newpass" > "${GEN_DIR}/${uid}.pass"
                info "  ${uid}: using manually set password"
                ((count_pass++)) || true
                ;;
        esac

        # Generate SSH keypair for every non-skip user
        local pubkey
        pubkey=$(gen_ed25519_keypair "$uid")
        printf '%s\n' "$pubkey" > "${GEN_DIR}/${uid}.pub"
        ((count_key++)) || true

    done < "${SESSION_DIR}/users.list"

    echo
    success "Generated: ${count_pass} password(s), ${count_key} SSH keypair(s), ${count_skip} skipped"
    echo
}
