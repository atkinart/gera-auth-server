package ru.gera.auth.user;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "app.bootstrap")
public class BootstrapUsersProperties {

    private List<BootstrapUser> users = new ArrayList<>();

    public List<BootstrapUser> getUsers() {
        return users;
    }

    public void setUsers(List<BootstrapUser> users) {
        this.users = users == null ? new ArrayList<>() : users;
    }

    public static class BootstrapUser {
        private String username;
        private String password;
        private String email;
        private String roles;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getRoles() {
            return roles;
        }

        public void setRoles(String roles) {
            this.roles = roles;
        }
    }
}
