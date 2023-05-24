package be.bastinjul.securitypreauthheader.users;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class CustomUser implements UserDetails {

    private final String username;
    private final String additionalInfo;
    private final List<String> roles;
    private final List<GrantedAuthority> authorities;

    public CustomUser(String username, String additionalInfo, List<String> roles) {
        this.username = username;
        this.additionalInfo = additionalInfo;
        this.roles = roles;
        this.authorities = new ArrayList<>();
        this.roles.forEach(role -> this.authorities.add(new SimpleGrantedAuthority(role)));
    }

    public String getAdditionalInfo() {
        return additionalInfo;
    }

    public List<String> getRoles() {
        return roles;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
