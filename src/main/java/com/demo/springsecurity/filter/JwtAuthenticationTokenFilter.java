package com.demo.springsecurity.filter;

import com.auth0.jwt.interfaces.Claim;
import com.demo.springsecurity.pojo.LoginUser;
import com.demo.springsecurity.utils.JwtUtil;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * @Author: Yupeng Li
 * @Date: 18/4/2024 20:35
 * @Description:
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    @Autowired
    RedisTemplate redisTemplate;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = request.getHeader("Authorization");

        /**如果token为空，放行到下一个过滤器*/
        if (token == null) {
            // 放行,不需要进行token验证。给后面的过滤器进行处理比如还有登录放行啥的
            filterChain.doFilter(request, response);
            // 这里必须要return，不然会继续往下执行去解析token，但是token是null，会报错
            return;
        }

        /** 解析token */
        try {
//            Map<String, Object> stringObjectMap = JwtUtil.parseToken(token);
            Claim claim = JwtUtil.parseToken(token);
        } catch (Exception e) {
            throw new RuntimeException("token无效");
        }

        /**验证token是否在redis中，如果不在，说明用户未登录*/
        LoginUser loginUser = (LoginUser) redisTemplate.opsForValue().get(token);
        if (loginUser == null) {
            throw new RuntimeException("用户未登录");
        }


        /**到这里说明token验证通过，用户已经登录，然后把用户信息存入SecurityContext中*/
        // TODO: 获取用户的权限信息，这里我们先不做处理
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginUser, null, loginUser.getAuthorities());
        // 把authenticationToken放入SecurityContext中
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        //token存在全部处理完之后放行
        filterChain.doFilter(request, response);
    }
}
