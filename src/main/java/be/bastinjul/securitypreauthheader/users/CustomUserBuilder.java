package be.bastinjul.securitypreauthheader.users;

import java.util.List;

public class CustomUserBuilder {
    private String username;
    private String additionalInfo;
    private List<String> roles;

    public CustomUserBuilder username(String username) {
        this.username = username;
        return this;
    }

    public CustomUserBuilder additionalInfo(String additionalInfo) {
        this.additionalInfo = additionalInfo;
        return this;
    }

    public CustomUserBuilder roles(List<String> roles) {
        this.roles = roles;
        return this;
    }

    public CustomUser build() {
        return new CustomUser(username, additionalInfo, roles);
    }
}