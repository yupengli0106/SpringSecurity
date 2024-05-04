package com.demo.springsecurity.pojo;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;

/**
 * @Author: Yupeng Li
 * @Date: 17/4/2024 18:01
 * @Description:
 */
@Data
//@AllArgsConstructor
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginUser implements org.springframework.security.core.userdetails.UserDetails{
    //把我们自己的用户信息放到这个类中
    private Students user;
    private List<String> permissions;//需要重新封装

    public LoginUser(Students user, List<String> permissions) {
        this.user = user;
        this.permissions = permissions;
    }

    // 处理redis序列化时的问题,不序列化authorities.注意：用jackjson
    @JsonIgnore
    private List<SimpleGrantedAuthority> authorities; // getAuthorities()方法返回的是GrantedAuthority对象
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (authorities != null) {
            return authorities;
        }
        // 通过stream流把permissions转换为GrantedAuthority对象
        // 因为框架中不会直接使用permissions，而是使用GrantedAuthority对象
        authorities = permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
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
