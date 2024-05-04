package com.demo.springsecurity.service.impl;

import com.demo.springsecurity.controller.Response.ResponseResult;
import com.demo.springsecurity.mapper.StudentsMapper;
import com.demo.springsecurity.pojo.LoginUser;
import com.demo.springsecurity.pojo.Students;
import com.demo.springsecurity.service.LoginService;
import com.demo.springsecurity.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * @Author: Yupeng Li
 * @Date: 17/4/2024 16:24
 * @Description:
 */

@Service
public class LoginServiceImpl implements LoginService {
    @Autowired
    StudentsMapper studentsMapper;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    RedisTemplate redisTemplate;

    @Override
    public ResponseResult login(Students student) {
        /**使用authenticationManager authenticate 进行用户认证*/
        //生成Authentication对象，传入用户名和密码
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(student.getUsername(), student.getPassword());
        //调用authenticate方法进行认证，这里必须要传入上一步转换的Authentication对象
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
        if (authenticate.isAuthenticated()) {
            /** 如果认证通过，生成token */
            //获取认证通过的用户信息, 为什么要强转为LoginUser，因为我们在自定义的UserDetailsService中返回的是LoginUser
            //getPrincipal()方法返回是用来存放用户信息的，这里存放的是LoginUser
            LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
            Integer studentID = loginUser.getUser().getStudentID();
            String username = loginUser.getUser().getUsername();
            //生成token,这里使用map存放用户信息，生成token
            Map<String, Object> map = Map.of("studentID", studentID, "username", username);
            String token = JwtUtil.genToken(map);

            /** 把完整的用户信息存入到redis中 token : user */
            //这里其实是可有可无的，因为没有在redis里面验证token。但是后续可以通过token获取用户信息权限等
            redisTemplate.opsForValue().set(token, loginUser);

            //这里是直接返回token，实际开发中可以返回一个map，里面存放key为token，value为token的值
            return new ResponseResult(200, "登录成功", token);

        }else {
            return new ResponseResult(500, "登录失败", null);
        }
    }

    /**
     * 退出登录
     * @param token 用户的token
     * @return 返回退出登录的结果
     * @Description: 根据token删除redis中的用户，清空SecurityContextHolder中的用户
     */
    @Override
    public ResponseResult logout(String token) {
        if (token == null || token.isEmpty()) {
            return new ResponseResult(400, "Token is empty or invalid", null);
        }
        try {
            // 根据token删除redis中的用户信息
            Boolean deleted = redisTemplate.delete(token);
            if (deleted == null || !deleted) {
                return new ResponseResult(404, "Token not found or already removed", null);
            }

            // 清空SecurityContextHolder中的用户
            // 因为使用了这里SpringSecurity使用到了ThreadLocal，所以不用担心线程安全问题
            // 因此这里清空当前线程的用户信息，如果是多线程的话，其他线程的用户信息不会被清空
            SecurityContextHolder.clearContext();

            return new ResponseResult(200, "Logged out successfully", null);
        } catch (Exception e) {
            // 添加日志记录异常
            // TODO: Add log to record exception
            return new ResponseResult(500, "Logout failed due to an internal error", null);
        }
    }

}
