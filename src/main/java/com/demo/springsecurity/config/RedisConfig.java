package com.demo.springsecurity.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.*;


/**
 * @Author: Yupeng Li
 * @Date: 18/4/2024 20:02
 * @Description: Redis configuration
 if we wanna serialize an object to store in redis, we need to configure the redis template.
 */

@Configuration
public class RedisConfig{

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
