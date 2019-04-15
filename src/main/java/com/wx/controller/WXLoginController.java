package com.wx.controller;

import java.util.HashMap;
import java.util.Map;

import com.wx.common.*;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.wx.model.WXSessionModel;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
public class WXLoginController implements HandlerInterceptor {

	private static final Logger logger = LoggerFactory.getLogger(WXLoginController.class);

	@Autowired
	private RedisOperator redis;
	@Autowired
	private  RedisTemplate redisTemplate;
	@PostMapping("/wxLogin")
	public JSONResult wxLogin(String code) {
		
		System.out.println("wxlogin - code: " + code);

//		https://api.weixin.qq.com/sns/jscode2session?
//				appid=APPID&
//				secret=SECRET&
//				js_code=JSCODE&
//				grant_type=authorization_code
		
		String url = "https://api.weixin.qq.com/sns/jscode2session";
		Map<String, String> param = new HashMap<>();
		param.put("appid", "wx0c5363552b7d437d");
		param.put("secret", "da3ddec82b6497b49d15a38f3eeb82c7");
		param.put("js_code", code);
		param.put("grant_type", "authorization_code");
		
		String wxResult = HttpClientUtil.doGet(url, param);
		System.out.println(wxResult);
		
		WXSessionModel model = JsonUtils.jsonToPojo(wxResult, WXSessionModel.class);
		// 3、获取自定义登陆态生成token,由openid和session_key生key=rd_session，value=openid
		String rd_session = UUIDUtils.get16UUID();

 		// 存入session到redis
		redis.set("user-redis-session:" + model.getOpenid(),
							model.getSession_key(),
							1000 * 60 * 30);

		// 通过加密算法把openid和session_key加密生成3rd_session
		redisTemplate.opsForValue().set(rd_session, model.getOpenid());

		return JSONResult.ok();
	}

	/**
	 * 前置处理器
	 * @param request
	 * @param response
	 * @param handler
	 * @return
	 * @throws Exception
	 */
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
		String token = request.getHeader("Authorization");
		logger.info("RequestURI:" + request.getRequestURI());
		String url = request.getRequestURI();
		logger.info("url: " + url);
		// 注册不做拦截
		for (String urlConfig : config.getLoginConfigs()) {
			if (StringUtils.contains(url, urlConfig)) {
				logger.info("登陆非拦截地址" + url);
				// 清除上次登陆的token
				if (StringUtils.isNotEmpty(token)) {
					logger.info("清除上次登陆的token：" + token);
					redisTemplate.delete(token);
				}
				return true;
			}
		}
		// 其他地址不拦截：字典数据和文件上传的接口
		for (String urlConfig : config.getOtherConfigs()) {
			if (StringUtils.contains(url, urlConfig)) {
				logger.info("其他非拦截地址" + url);
				return true;
			}
		}
		// 验证token是否存在
		logger.info("Authorization：" + token);
		if (StringUtils.isEmpty(token)) {
			logger.info("token参数为空");
			return false;
		}
		// 获取redis中的session_key和openid
		String rd_session = (String) redisTemplate.opsForValue().get(token);
		if (rd_session == null) {
			logger.info("token失效:" + token);
			return false;
		}
		logger.info("token存在，验证成功！");
		return true;
	}

	@Override
	public void postHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o, ModelAndView modelAndView) throws Exception {

	}

	@Override
	public void afterCompletion(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o, Exception e) throws Exception {

	}


}
