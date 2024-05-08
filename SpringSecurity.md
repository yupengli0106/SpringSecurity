# SpringSecurity

**SpringSecurity的内部执行流程，这里刚开始就简单看下有什么就行了不需要理解，后面在实际的代码操作中会一步步的去接触和理解，记得多回头来看看这张图。**

Reference：[三更草堂 （SpringSecurity框架教程-Spring Security+JWT实现项目级前端分离认证授权）](https://www.bilibili.com/video/BV1mm4y1X7Hc?p=1)

![SpringSecurity](../SpringSecurity/images/SpringSecurity.png)

## Login基本步骤

SpringSecurity 有属于自己的Login接口，每次用户登陆时会首先从内存中SecuirtContextHolder里面查找是否有用户。但是，在实际的开发中我们有自己的数据库，在验证用户的时候需要去查询我们自己的数据库然后进行用户名和密码的比对。最后，比对成功后需要将我们的用户存到SecuirtContextHolder中以便后续的login。(注意这里要有**SpringSecurity依赖**)

因此，为了实现这一目的我们首先要：

1. 连接好自己的数据库，然后写好mapper方法并进行测试e.g. findByUserName()

```java
@Mapper
public interface SystemUserMapper {
  
    @Select("select * from sys_user where username = #{username}")
    SystemUser findByUsername(String username);
  
}
```

2. 实现Spring Security中的**UserDetailsService接口**(**必须实现)**

```java
@Service
public class UserDetailServiceImpl implements UserDetailsService{
    @Autowired
    SystemUserMapper systemUserMapper;;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //查询用户的信息在我们的数据库中，而不是在内存中
        //这里我们使用我们自己的数据库来查询用户信息
        SystemUser user = systemUserMapper.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }else {
            // 把我们上面查到的用户信息封装到我们自己的LoginUser中
            return new LoginUser(user);
        }
    }
}
```

实现这里的接口和方法，就是为了在login的时候去查询我们自己的数据库数据进行比对。在查询到用户后开始处理：如果用户不存在则直接提示“用户不存在”，如果用户存在则需要返回一个UserDetails对象根据loadUserByUsername()方法的返回值。但是这个时候我们还没有UserDetails对象，我们会在下一步创建。

3. 这里我们可以自己创建一个名为LoginUser的类在pojo下，但是必须继承Spring security提供的**UserDetails接口**！

**这里一定要注意 `private List<SimpleGrantedAuthority> `authorities;这个对象不能被Redis序列化，所以这里一定要先处理JsonIgnore ！！**！

```java
@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginUser implements org.springframework.security.core.userdetails.UserDetails{
    //把我们自己的用户信息放到这个类中
    private SystemUser user;
  
  	//这里一定要先写出来虽然可以先不做权限的控制，不然redis序列化会报错！
   	@JsonIgnore
    private List<SimpleGrantedAuthority> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
      	//这里先不管权限设置返回null
        return null;
    }
  
    @Override
    public String getPassword() {
      	//根据我们自己的用户返回用户的信息，springsecurity会自己调用这里的方法
        return user.getPassword();
    }

    @Override
    public String getUsername() {
      	//根据我们自己的用户返回用户的信息，springsecurity会自己调用这里的方法
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
      	//先自己手动给权限，不然不通过验证
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
      	//先自己手动给权限，不然不通过验证
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
      	//先自己手动给权限，不然不通过验证
        return true;
    }

    @Override
    public boolean isEnabled() {
        //先自己手动给权限，不然不通过验证
        return true;
    }
}
```

这里我们算是有了一个LoginUser对象也就是UserDetails对象，然后需要把这个对象在上一步的return中返回给SpringSecurity。**再后面SpringSecurity收到前端用户名和密码会通过自己封装成一个Authentication对象，然后这个对象会被AuthenticationProvider进行验证，这时候的验证就会涉及我们前面实现的UserDetailsService接口，然后根据我们返回的UserDetails也就是LoginUser对象来进行密码和用户名的比对！**

4. 到这里我们基本已经完成了通过SpringSecurity自己的登陆界面，然后查询我们自己的数据库进行验证的过程。但是这个时候我们启动项目验证用户名和密码登录会发现项目报错，e.g. There is no PasswordEncoder mapped for the id "null". 

这个报错的原因是因为我们后端的密码是明文保存的并没有PasswordEncoder进行加密后的保存，但是SpringSecurity在检查密码的时候会通过PasswordEncoder检查，这就是导致我们报错的原因。**PasswordEncoder要求数据的密码格式为{id}password.**

解决方式主要有两种：**1.** 在明文密码前面加上{noop},比如{noop}mypassword这个时候SpringSecutiry在检查的时候就知道你使用的明文检查米啊吗。**2.** 这也是最常用的方法，就是我们配置SpringSecutiry的config，然后对我们的密码进行加密处理后再存到数据库就没问题了。（这是我们应该做的正确的选择，下面会讲到如何加密密码）。

## 密码加密

密码加密，上面提到PasswordEncoder要求数据的密码格式为{id}password.但是这样过于麻烦且不方便，于是现在的做法都是**使用CryptPasswordEncoder替换PasswordEncoder**。

实现CryptPasswordEncoder也很简单，只需要把CryptPasswordEncoder对象注入到Spring容器中就行(@Bean)，后续SpringSecurity就会默认使用它来进行密码校验了。

具体步骤为：自定义SpringSecurity的配置类，然后必须继承WebSecurityconfigurerAdapter, 或者现在更为流行的是直接使用@EnableWebSecurity 注解。

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    /**
     * Password encoder
     * @return BCryptPasswordEncoder instance.
     * @Description: Password encoder for password encryption and decryption.
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

需要注意的是在用户登录成功的时候记得通过BCryptPasswordEncoder把加密后的密码存到数据库中去，至此，基本SpringSecurity登录验证的步骤已经完成。

## Token生成

使用JWT生成token，以下代码为写好的工具类，注意需要jwt依赖。

```xml
<!-- JWT -->
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>4.4.0</version>
</dependency>
```

```java
package com.demo.springsecurity.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Date;
import java.util.Map;

public class JwtUtil {

    private static final String SECRET_KEY = "***I bet you can't guess this secret key :)***";
    private static final String ISSUER = "os-wombat"; // application name
    private static final long EXPIRATION_TIME = 24 * 60 * 60 * 1000; // 24h

    /**
     * 生成token
     * @param claims 业务数据 例如用户id 用户名等
     * @return token
     */
    public static String genToken(Map<String, Object> claims) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY); // 使用密钥初始化算法
            return JWT.create()
                    .withClaim("userClaims", claims) // 更明确地命名claims
                    .withIssuer(ISSUER) // 添加发行者
                    .withIssuedAt(new Date()) // 添加令牌发行时间
                    .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))// 过期时间
                    .sign(algorithm); // 签名
        } catch (Exception e) {
            throw new RuntimeException("Error generating token", e);
        }
    }


    public static Map<String, Object> parseToken(String token) {
        try {
            // 使用同一个密钥和算法初始化一个JWT验证器
            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(ISSUER)  // 如果在生成token时指定了发行者，这里需要检查
                    .build();// Reusable verifier instance

            // 使用验证器验证token
            DecodedJWT jwt = verifier.verify(token);
            return jwt.getClaim("userClaims").asMap();//返回解析的用户数据作为map返回
        } catch (Exception e) {
            throw new RuntimeException("Error parsing token", e);
        }

    }


}

```

## 登录接口(Login Controller)具体实现

1. **登录放行。由于SpringSecurity对所有的接口默认都要进行验证，但是这样导致了我们自己定义的/login路径没法访问，因此我们这里的第一步就是要对我们自定义的/login接口进行放行。** 

```java
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig{
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .sessionManagement(sessionManagement -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 不通过session获取security context

                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/users/login").permitAll()// permit /user/login request without authentication
                        .anyRequest().authenticated() )// any other request need to be authenticated

                .csrf(AbstractHttpConfigurer::disable) // disable csrf
                .httpBasic(Customizer.withDefaults());; // basic authentication
        return http.build();
    }
```



2. **通过AuthenticationManager的authenticate方法来进行用户认证，所以需要在SecurityConfig中配置AuthenticationManager注入容器.**

```java
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig{
    @Bean
    public AuthenticationManager authenticationManagerBean(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class).build();
    }
}
```



3. **用户认证成功的话通过JWT生成Token然后把Token放入返回体中返还给前端，同时用户信息存入Redis可以用id作为key。**

这里需要先有Redis的依赖

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

因为我们的Redis中存储的是一个Object所以需要配置Redis Config进行序列化设置，简单key和value则不用。

```java
/**
*if we wanna serialize an object to store in redis, we need to configure the redis template!
*/
@Configuration
public class RedisConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
      
        // Key serializer
        template.setKeySerializer(new StringRedisSerializer());

        // Use Jackson 2 Json Redis Serializer for value
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());

        return template;
    }
}
```

## Login Controller 代码总结

```java
@Service
public class LoginServiceImpl implements LoginService {
    @Autowired
    SystemUserMapper systemUserMapper;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    RedisTemplate redisTemplate;

    @Override
    public ResponseResult login(SystemUser user) {
      /**使用authenticationManager authenticate 进行用户认证*/
      //生成Authentication对象，传入用户名和密码
      UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
      //调用authenticate方法进行认证，这里必须要传入上一步转换的Authentication对象
      Authentication authenticate = authenticationManager.authenticate(authenticationToken);
      if (authenticate.isAuthenticated()) {
        /** 如果认证通过，生成token */
        //获取认证通过的用户信息, 为什么要强转为LoginUser，因为我们在自定义的UserDetailsService中返回的是LoginUser
        //getPrincipal()方法返回是用来存放用户信息的，这里存放的是LoginUser
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        Long userID = loginUser.getUser().getId();
        String username = loginUser.getUser().getUsername();
        //生成token,这里使用map存放用户信息，生成token
        Map<String, Object> map = Map.of("userID", userID, "username", username);
        String token = JwtUtil.genToken(map);
        
        /** 把完整的用户信息存入到redis中 token : user */
        //这里其实是可有可无的，因为没有在redis里面验证token。但是后续可以通过token获取用户信息权限等
        redisTemplate.opsForValue().set(token, loginUser);
                                        
        //这里是直接返回token，实际开发中可以返回一个map，里面存放key为token，value为token的值
        return ResponseResult.success(token);
      }else {
        return ResponseResult.error(400,"登录失败");
      }
    }
}
```

## Login 成功后存入ContextHolder

认证成功后我们需要定义一个认证过滤器（在UsernamePasswordAuthenticationFliter之前执行）：

1. 获取token
2. 解析token获取userid
3. 从redis从获取用户信息
4. 存入SecurityContextHolder

以下为上面步骤的代码解决方案：

```java
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
            Map<String, Object> stringObjectMap = JwtUtil.parseToken(token);
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
        //token存在全部处理完之后放行
        filterChain.doFilter(request, response);
    }
}
```

5. 这里还有最关键的最后一步配置，**把我们自己定义好的Filter添加到SpringSecurityConfig中**，且我们要知道在哪个哪个过滤器之前执行，这里就是要在UsernamePasswordAuthenticationToken验证之前执行，具体参照Security执行流程图。

```java
              .addFilterBefore(jwtAuthenticationTokenFilter,UsernamePasswordAuthenticationFilter.class);
```

```java
public class SpringSecurityConfig{
 		@Autowired
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;
  
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .sessionManagement(sessionManagement -> sessionManagement
                                   
                 ...中间代码省略...
                                   
                // Add custom JWT filter before UsernamePasswordAuthenticationFilter！
                .addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }
}
```

## Logout退出

这里我们通过前端的get请求，然后获取到用户的token。接着在Redis中根据key也就是token来删除用户的信息，再在SecurityContextHolder中删除当前用户的信息。

清空SecurityContextHolder中的用户时不需要担心清空所有用户，因为使用了这里SpringSecurity使用到了ThreadLocal，所以不用担心线程安全问题。因此这里清空当前线程的用户信息，如果是多线程的话，其他线程的用户信息不会被清空。

1. Controller

```java
    @GetMapping("/logout")
    public ResponseResult logout(HttpServletRequest request){
        return loginService.logout(request.getHeader("Authorization"));
    }
```

2. LoginService

```java
@Override
public ResponseResult logout(String token) {
  if (token == null || token.isEmpty()) {
    return new ResponseResult(400, "Token is empty or invalid", null);
  }
  try {
    // 根据token删除redis中的用户信息
    Boolean deleted = redisTemplate.delete(token);
    
    if (deleted == null || !deleted) {
      return ResponseResult.error(400,"Token is empty or invalid");
    }
    
    // 清空SecurityContextHolder中的用户
    // 因为使用了这里SpringSecurity使用到了ThreadLocal，所以不用担心线程安全问题
    // 因此这里清空当前线程的用户信息，如果是多线程的话，其他线程的用户信息不会被清空
    SecurityContextHolder.clearContext();
    
    return ResponseResult.error(400,"Token not found or already removed");
    
  } catch (Exception e) {
    // 添加日志记录异常
    // TODO: Add log to record exception
    return ResponseResult.error(500, "Internal Server Error");
  }
}
```

## 用户授权

1. 开启配置文件 `@EnableGlobalMethodSecurity(prePostEnabled = true)`

```java
...
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SpringSecurityConfig {
  ...
}
```

Controller 路径权限控制 `@PreAuthorize("hasAnyAuthority('admin')")`, 这里hasAnyAuthority()是SpringSecurity提供的方法，‘admin’是权限我们自己定义的权限。

```java
@GetMapping("/permission")
@PreAuthorize("hasAnyAuthority('admin')")
public String auth(){
  return "permission test";
}
```

2. 封装权限信息

2.1 在UserDetailServiceImpl中写好用户的权限(List<String> permissions)，这里就先写死实际开发可以从数据库获取. 

```java
@Service
public class UserDetailServiceImpl implements UserDetailsService{
    @Autowired
    SystemUserMapper systemUserMapper;;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //查询用户的信息在我们的数据库中，而不是在内存中
        //这里我们使用我们自己的数据库来查询用户信息
        SystemUserMapper user = systemUserMapper.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }else {
          
            // 把我们上面查到的用户信息封装到我们自己的LoginUser中
            // 这里我们先写死权限，在实际开发中，我们可以通过查询数据库来获取用户的权限
    				// 必须传入list
            List<String> permissions = new ArrayList<>(Arrays.asList("test","admin"));
            return new LoginUser(user,permissions);
        }
    }
}
```

2.2 修改LoginUser类中的有参构造方法和getAuthorities()方法。注意：@JsonIgnore防止Redis序列化报错

```java
@Data
//@AllArgsConstructor
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginUser implements org.springframework.security.core.userdetails.UserDetails{
    //把我们自己的用户信息放到这个类中
    private SystemUser user;
    private List<String> permissions;//需要重新封装
  
  	// 有参构造
    public LoginUser(SystemUser user, List<String> permissions) {
        this.user = user;
        this.permissions = permissions;
    }

    // 处理redis序列化时的问题,不序列化authorities.注意：用jackjson
    @JsonIgnore
    private List<SimpleGrantedAuthority> authorities;// getAuthorities()方法返回的是GrantedAuthority对象
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
  
  以下其他方法省略......
}

```

最后还需要注意我们之前定义的JWTFilter中有没有获取权限

```java
UsernamePasswordAuthenticationToken authenticationToken =
          new UsernamePasswordAuthenticationToken(loginUser, null, loginUser.getAuthorities());
```

## ROAC (role based access control) 权限模型

1. 首先需要搞懂ROAC模型的原理，以及各个表之间的关系 。

   **1.1.**  一个角色拥(role)有一组权限(menu): 比如在角色表里面id为1的，可以拥有权限表里面id为1-3的权限，分别为添加，查看，删除。而角色表里面id为2的，可以拥有权限表里面id为2的权限，只可以查看，不允许添加和删除。

   重点：**role_menu表**先根据角色然后分配可以拥有哪些权限（关联角色表和权限表）

   **1.2** 一个角色(role)可以对呀多个用户(user), e.g. 公司里面有一个CEO，有多个HR。（这里就是关联角色表和用户表）

   重点：**user_role表**根据userID再去关联role_menu里的roleID (最后我们实际的分配默认用户权限的时候就是根据user_role这张表来配置的！！！)

   

   ![ROAC](../SpringSecurity/images/ROAC.png)

   

2. 建表以及sql语句的编写： 这里直接参考代码就行

3. 从数据库中查询权限信息（涉及mybatis）

​	**3.1.** 写好pojo类，数据库映射, 这里用到了java的JPA个人感觉会比之前更加清晰。

```xml
<!--这里不要忘记添加依赖-->
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
```

```java
package com.demo.springsecurity.pojo;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "sys_user")
public class SystemUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", nullable = false, unique = true)
    private String username;

    @Column(name = "nick_name")
    private String nickname;

    private String password;
    private String status;
    private String email;

    @Column(name = "phone_number")
    private String phoneNumber;

    private String sex;
    private String avatar;

    @Column(name = "user_type", nullable = false)
    private String userType;

    @Column(name = "create_by")
    private Long createBy;

    @Column(name = "create_time")
    @Temporal(TemporalType.TIMESTAMP)
    private Date createTime;

    @Column(name = "update_by")
    private Long updateBy;

    @Column(name = "update_time")
    @Temporal(TemporalType.TIMESTAMP)
    private Date updateTime;

    @Column(name = "del_flag", nullable = false)
    private Integer delFlag;
}
```

​	**3.2.** 编写mapper和mybatis配置文件

```java
package com.demo.springsecurity.mapper;

import org.apache.ibatis.annotations.Mapper;
import java.util.List;

@Mapper
public interface MenuMapper {
  	/**
     * 根据用户id查询用户权限
     * @param userId 用户id
     * @return 用户权限list
     */ 
    List<String> selectPermsByUserId(Long userId);
}
```

```yml
# MyBatis configuration 
mybatis:
  mapper-locations: classpath:mapper/*.xml
  configuration:
    map-underscore-to-camel-case: true
```

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">

<!--属于动态sql会在SystemUserMapper里面被调用-->
<mapper namespace="com.demo.springsecurity.mapper.MenuMapper">
  
    <select id="selectPermsByUserId" resultType="java.lang.String">
        select
            distinct m.perms
        from
            sys_user_role ur
                left join sys_role r on ur.role_id = r.id
                left join sys_role_menu rm on ur.role_id = rm.role_id
                left join sys_menu m on m.id= rm.menu_id
        where
            user_id = #{userId}
          and r.status = 0
          and m.status = 0;
    </select>

</mapper>
```

​	**3.3.** 最后在UserDetailServiceImpl里面查询数据库获取用户权限。

```java
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        省略
        ......
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }else {
            // 把我们上面查到的用户信息封装到我们自己的LoginUser中
            //这里就是实际开发中，通过查询数据库来获取用户的权限! 
            List<String> permissions = menuMapper.selectPermsByUserId(user.getId());
            return new LoginUser(user,permissions);
        }
    }
```



## 自定义失败异常处理

这里的目的是在认证失败或者授权失败的情况下也能和我们的接口一样返回相同的结构的json给前端处理，这里就需要我们知道SpringSecurity的异常处理机制。

在SpringSecurity中，认证或者授权异常会被ExceptoinTranslationFilter捕获到，进而去判断是认证失败还是授权失败。

+ **认证失败**：认证失败的异常会被封装成AuthenticationException然后调用**AuthenticationEntryPoint**对象的方法进行异常处理。

+ **授权失败**：授权失败的异常会被封装成AccessDeniedException然后调用**AccessDeniedHandler**对象的方法进行异常处理。

**为了自定义处理以上两种异常我们可以先自定义实现类，然后再配置给SpringSecurity！**



1. **自定义实现类：**

AuthenticationEntryPoint：

```java
@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        // 自定义认证失败的返回结果
        ResponseResult errorResult = ResponseResult.error(401, "认证失败，请重新登录");
        // 处理异常，将结果转换为JSON字符串
        WebUtil.renderJson(response, errorResult);

    }
}
```

AccessDeniedHandler:

```java
@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // 自定义权限不足的返回结果
        ResponseResult responseResult = ResponseResult.error(403, "权限不足，请联系管理员");
        // 处理异常，将结果转换为JSON字符串
        WebUtil.renderJson(response, responseResult);
    }
}
```



2. **WebUtil工具类**：

   在我们自定义的异常处理类中我们用到了工具类**WebUtil**这是因为，SpringSecurity默认返回的会是response原生对象，但是我们我们需要统一**返回自定义响应体ResopnseResult的json格式数据**。因此我们借助一个工具类将返回的ResopnseResult对象转换成json格式返还给前端。

```xml
<!--fastjson 依赖-->
<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>fastjson</artifactId>
    <version>2.0.0</version>
</dependency>
```

```java
/**
 * @Author: Yupeng Li
 * @Date: 4/5/2024 16:40
 * @Description: Web工具类,用于渲染JSON数据。
 * 由于Spring Security的异常处理类只能返回字符串，但是我们需要返回我们自定义的ResponseResult对象,且ResponseResult对象需要转换为JSON字符串。
 * 所以我们需要一个工具类来将对象渲染为JSON字符串,然后返回给前端。
 */

public class WebUtil {
    /**
     * Renders an object as JSON to the HTTP response.
     *
     * @param response the HTTP response object
     * @param object the object to render as JSON
     */
    public static void renderJson(HttpServletResponse response, Object object) {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        try {
            String json = JSON.toJSONString(object);
            response.getWriter().write(json);
        } catch (IOException e) {
            // Log the exception if any
            e.printStackTrace();
        }
    }
}
```



3. **配置SpringSecurity文件**

```java
public class SpringSecurityConfig {
  @Autowired
  private AuthenticationEntryPointImpl authenticationEntryPointImpl
  @Autowired
  private AccessDeniedHandlerImpl accessDeniedHandlerImpl;
  
  @Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
            省略
      			......
      
            // Add custom exception handling
            .exceptionHandling(exceptionHandling -> exceptionHandling
                    .authenticationEntryPoint(authenticationEntryPointImpl)
                    .accessDeniedHandler(accessDeniedHandlerImpl)
                               
    return http.build();
	}
}
```



## 权限校验的其他方法

这里权限检验还有其他方法：

1. 通过重写一个权限类我们可以实现自己的权限控制检查方法
2. 还可以通过配置文件对api访问权限进行控制

目前不需要了解太多，以后在项目中碰到根据需求可以在进一步的探究

## CORS跨域问题

跨域问题仅仅通过配置SpringBoot是不够的，还必须要在SpringSecurity中也允许跨域。(更新：这里目前好像不需要配置SpringBoot只需要配置SpringSecurity就行)

在SperingSecurityConfig里面写配置方法：

```java
/**
* Cors configuration source
* @return CorsConfigurationSource instance
* @Description: CorsConfigurationSource is the interface used to configure cors related beans.
*/
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration corsConfiguration = new CorsConfiguration();
    //TODO: 这里目前是允许所有的请求，实际开发中需要修改为为线上环境的域名
    corsConfiguration.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
    corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
    corsConfiguration.setAllowedHeaders(Arrays.asList("*"));
    corsConfiguration.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", corsConfiguration);

    return source;
}
```

在filterChain()中配置cors：

```java
.cors(cors -> cors.configurationSource(corsConfigurationSource())) // enable cors
```

## CSRF

在前后端分离的项目中CSRF已经不再是一个问题，在springsecurity配置中我们必须要配置.disable。如果不关闭的话会进行双重的token认证，一个是我们自己的token 一个是SpringSecurity自己的csrf-token认证。

## 认证成功/认证失败/注销成功 处理器

在这认证成功/认证失败/注销成功 之后我们都可以执行相应的逻辑如果有需要的话，这里不展开解释，以后根据开发需求再进行配置。



## ResponseResult 返回响应体以后参考

```java
package com.demo.springsecurity.controller.Response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;

/**
 * @Author: Yupeng Li
 * @Date: 17/4/2024 16:26
 * @Description:
 */

@Data
@AllArgsConstructor
public class ResponseResult {
    private final Integer code;
    private final String message;
    private final Object data;

    public static ResponseResult success(Object data) {
        return new ResponseResult(200, "Success", data);
    }

    public static ResponseResult error(Integer code, String message) {
        return new ResponseResult(code, message, null);
    }

    public static ResponseResult error(ErrorEnum errorEnum) {
        return new ResponseResult(errorEnum.getCode(), errorEnum.getMessage(), null);
    }

    @Getter
    public enum ErrorEnum {
        // 定义错误码枚举
        INTERNAL_SERVER_ERROR(500, "Internal Server Error"),
        BAD_REQUEST(400, "Bad Request"),
        NOT_FOUND(404, "Not Found");

        private final Integer code;
        private final String message;

        ErrorEnum(Integer code, String message) {
            this.code = code;
            this.message = message;
        }

    }
}
```

## 用户注册（Register）及默认权限分配（ROAC）

用户注册后存入数据库，已经根据ROAC的数据库设计来进行默认权限的分配。（这里可能需要进一步的改进，不是很自信）。

1. 编写Controller

```java
@PostMapping("/register")
public ResponseResult registerNewUser(@RequestBody SystemUser user){
  return registerService.registerNewUser(user);
}
```

2. 实现RegisterService类

```java
/**
 * @Author: Yupeng Li
 * @Date: 4/5/2024 14:08
 * @Description: Register new user
 */
@Service
public class RegisterServiceImpl implements RegisterService {
    @Autowired
    private SystemUserMapper systemUserMapper;

    @Autowired
    private SystemUserRoleMapper systemUserRoleMapper;

    @Autowired
    private BCryptPasswordEncoder PasswordEncoder;

    @Override
    public ResponseResult registerNewUser(SystemUser newUser) {
        String username = newUser.getUsername();
        String password = newUser.getPassword();
        String hashPassword = PasswordEncoder.encode(password);

        // Check if the username already exists
        if (systemUserMapper.findByUsername(username) != null) {
            return ResponseResult.error(400, "用户名已存在");
        }

        //insert new user into database
        systemUserMapper.insertNewUser(username, hashPassword);
        //get the user id
        SystemUser user = systemUserMapper.findByUsername(username);
        if (user == null) {
            return ResponseResult.error(500, "用户注册失败");
        }

        //set default role for the new user
        Long userID = user.getId();
        systemUserRoleMapper.setDefaultRole(userID);

        return ResponseResult.success("注册成功");
    }
}
```



3. 编写SystemUserRoleMapper

```java
@Mapper
public interface SystemUserRoleMapper {
    /**
     * Set the default role for the new user
     * @param userID the ID of the new user
     * @Description: The default role is the role with ID 1, means the user can only query the data.
     */
    @Insert("insert into sys_user_role(user_id, role_id) values(#{userID}, 1)")
    void setDefaultRole(Long userID);
}
```

在SystemUserMapper中添加查询用户的方法,  在register的时候用来查询用户是否存在

```java
@Insert("insert into sys_user(username, password) values(#{username}, #{password})")void insertNewUser(String username, String password);
```



4. SystemUserRole 的实体类POJO

   ```java
   /**
    * @Author: Yupeng Li
    * @Date: 8/5/2024 15:54
    * @Description: 这是一个系统用户角色实体类，用于描述系统用户的角色信息。
    * 比如：userID  roleID
    *          1       1（查询,删除）
    *          2       2（查询）
    *
    *说明：userID为用户ID，roleID为角色ID，这两个字段是外键，分别关联了sys_user表和sys_role_menu表。
    *              roleID为1: 查询,删除
    *              roleID为2: 查询
    *  
    *  这里的roleID为1和2是在sys_role_menu表中定义的，分别对应了查询和删除的权限。
    */
   @Table(name = "sys_user_role")
   public class SystemUserRole {
       @Column(name = "user_id", nullable = false)
       private Integer userID;
   
       @Column(name = "role_id", nullable = false)
       private Integer roleID;
   }
   
   ```

   

5. 最后需要在SpringSecurConfig配置文件中，放心/register 路径才能访问

```java
  @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
          			省略
          			......
      
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/users/login","/users/register").permitAll()// permit request without authentication
                        .anyRequest().authenticated() )// any other request need to be authenticated

        return http.build();
    }
```



# 附件：数据库

**Sys_user:**

```sql
-- auto-generated definition
create table sys_user
(
    id           bigint auto_increment comment '用户ID'
        primary key,
    username     varchar(64) default ''  not null comment '用户名',
    nick_name    varchar(64) default ''  not null comment '昵称',
    password     varchar(64) default ''  not null comment '密码',
    status       char        default '0' null comment '账号状态（0正常 1停用）',
    email        varchar(64)             null comment '邮箱',
    phone_number varchar(32)             null comment '手机号',
    sex          char                    null comment '用户性别（0男，1女，2未知）',
    avatar       varchar(128)            null comment '头像',
    user_type    char        default '1' not null comment '用户类型（0管理员，1普通用户）',
    create_by    bigint                  null comment '创建人的用户ID',
    create_time  datetime                null comment '创建时间',
    update_by    bigint                  null comment '更新人',
    update_time  datetime                null comment '更新时间',
    del_flag     int         default 0   null comment '删除标志（0代表未删除，1代表已删除）'
)
    comment '系统用户';

```

**Sys_menu:**

```sql
-- auto-generated definition
create table sys_menu
(
    id          bigint auto_increment
        primary key,
    menu_name   varchar(64)  default ''  not null comment '菜单名称',
    path        varchar(200)             null comment '路由地址',
    component   varchar(255)             null comment '组件路径',
    perms       varchar(100)             null comment '权限标识',
    icon        varchar(100) default '#' null comment '菜单图标',
    create_by   bigint                   null,
    create_time datetime                 null,
    update_by   bigint                   null,
    update_time datetime                 null,
    del_flag    int          default 0   null comment '是否删除（0未删除 1已删除）',
    remark      varchar(500)             null comment '备注',
    visible     int          default 1   null comment '是否可见（0不可见 1可见）',
    status      int          default 1   null comment '菜单状态（0正常 1停用）'
)
    comment '系统菜单';


```

**Sys_role:**

```sql
-- auto-generated definition
create table sys_role
(
    id          bigint auto_increment
        primary key,
    name        varchar(128)     null comment '角色名称',
    role_key    varchar(100)     null comment '角色权限字符串',
    status      char default '0' null comment '角色状态（0正常 1停用）',
    del_flag    int  default 0   null comment '删除标志',
    create_by   bigint           null,
    create_time datetime         null,
    update_by   bigint           null,
    update_time datetime         null,
    remark      varchar(500)     null comment '备注'
)
    comment '系统角色';

```

**Sys_role_menu:**

```sql
-- auto-generated definition
create table sys_role_menu
(
    role_id bigint auto_increment comment '角色ID',
    menu_id bigint default 0 not null comment '菜单ID',
    primary key (role_id, menu_id)
);
```

**Sys_user_role:**

```sql
-- auto-generated definition
create table sys_user_role
(
    user_id bigint auto_increment comment '用户ID',
    role_id bigint default 0 not null comment '角色ID',
    primary key (user_id, role_id)
);
```

权限检查测试sql语句：

```sql
/* 根据userid查询perms对应的role和menu都必须是正常状态的 */
select
    distinct m.perms
from
    sys_user_role ur
    left join sys_role r on ur.role_id = r.id
    left join sys_role_menu rm on ur.role_id = rm.role_id
    left join sys_menu m on m.id= rm.menu_id
where
    user_id = 6 /* 这里在代码中需要根据实际用户id进行查询，不能写死*/
    and r.status = 0
    and m.status = 0;
```

1. **SELECT DISTINCT m.perms**

- `SELECT DISTINCT` 关键字用于返回唯一的（去重的）权限记录。
- `m.perms` 指的是 `sys_menu` 表中的 `perms` 字段，代表特定的权限，例如“编辑”、“删除”等。

2. **FROM sys_user_role ur**

- 查询的起点是 `sys_user_role` 表，该表存储用户和角色之间的关系，其中 `ur` 是表的别名。

3. **LEFT JOIN sys_role r ON ur.role_id = r.id**

- 通过 `LEFT JOIN` 语句，将 `sys_user_role` 表和 `sys_role` 表连接起来，使用 `role_id` 字段。
- 这一步将用户关联到他们的角色。

4. **LEFT JOIN sys_role_menu rm ON ur.role_id = rm.role_id**

- 再次使用 `LEFT JOIN` 将用户角色关联到具体的权限。这里通过角色的 `role_id` 将 `sys_role` 表和 `sys_role_menu` 表连接。
- `sys_role_menu` 表包含角色和权限（菜单项）之间的关系。

5. **LEFT JOIN sys_menu m ON m.id = rm.menu_id**

- 最后，使用 `LEFT JOIN` 将 `sys_role_menu` 表和 `sys_menu` 表连接，通过 `menu_id` 字段。
- `sys_menu` 表包含具体的权限信息，如权限名称。

6. **WHERE user_id = #{userId}**

- 此条件限定查询结果只关于特定的用户，`#{userId}` 是一个参数占位符，需要在执行时被实际的用户ID替换。

7. **AND r.status = 0 AND m.status = 0**

- 这两个条件确保只查询出活跃（有效）的角色和权限。`status = 0` 通常表示记录是活跃的。



