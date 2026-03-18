package ru.gera.auth.user;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class MongoUserDetailsManager implements UserDetailsManager {

    private final UserRepository users;

    public MongoUserDetailsManager(UserRepository users) {
        this.users = users;
    }

    @Override
    public void createUser(UserDetails user) {
        Assert.notNull(user, "user cannot be null");
        if (users.existsById(user.getUsername())) {
            throw new IllegalArgumentException("User already exists: " + user.getUsername());
        }

        UserEntity entity = new UserEntity();
        entity.setUsername(user.getUsername());
        entity.setPassword(user.getPassword());
        entity.setEnabled(user.isEnabled());
        entity.setRoles(toRoleSet(user));
        users.save(entity);
    }

    @Override
    public void updateUser(UserDetails user) {
        Assert.notNull(user, "user cannot be null");
        UserEntity entity = users.findById(user.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException(user.getUsername()));
        entity.setPassword(user.getPassword());
        entity.setEnabled(user.isEnabled());
        entity.setRoles(toRoleSet(user));
        users.save(entity);
    }

    @Override
    public void deleteUser(String username) {
        users.deleteById(username);
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {
        Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
        if (currentUser == null) {
            throw new AccessDeniedException("No authenticated user available");
        }

        String username = currentUser.getName();
        UserEntity entity = users.findById(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));
        entity.setPassword(newPassword);
        users.save(entity);
    }

    @Override
    public boolean userExists(String username) {
        return users.existsById(username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = users.findById(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));

        String[] authorities = user.getRoles().isEmpty()
                ? new String[]{"ROLE_USER"}
                : user.getRoles().toArray(String[]::new);

        return User.withUsername(user.getUsername())
                .password(user.getPassword())
                .disabled(!user.isEnabled())
                .authorities(authorities)
                .build();
    }

    private Set<String> toRoleSet(UserDetails user) {
        Set<String> roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(value -> value != null && !value.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));

        if (roles.isEmpty()) {
            roles.add("ROLE_USER");
        }
        return roles;
    }
}
