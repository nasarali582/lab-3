package iam

deny[msg] {
  user := input.users[_]
  user.role == "Administrator"

  not has_mfa(user)

  msg := sprintf("Admin user '%s' does not have MFA properly enabled", [user.username])
}

has_mfa(user) {
  user.mfa_enabled == true
}
