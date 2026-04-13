package main

deny[message] {
  some i
  user := input.users[i]
  user.role == "Administrator"
  not user.mfa_enabled
  message := sprintf("Admin user '%s' does not have MFA enabled.", [user.username])
}
