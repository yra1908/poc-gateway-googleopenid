/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.security.reactive.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.security.oauth2.gateway.TokenRelayGatewayFilterFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;

@Controller
@SpringBootApplication
public class GatewayApplication {

	@Autowired
	private TokenRelayGatewayFilterFactory filterFactory;

	@Autowired
	private MyGatewayFilterFactory myFilter;

	@Bean
	public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
		return builder.routes()
				.route("resource", r -> r.path("/resource")
						.filters(f -> f.filter(filterFactory.apply()).filter(myFilter.apply(new MyGatewayFilterFactory.Config())))
						.uri("http://localhost:9000"))
				.build();
	}

	@Bean
	public RestTemplate vanillaRestTemplate(){
		return new RestTemplate();
	}

	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
		// @formatter:off
		return http
				.authorizeExchange()
				.matchers(EndpointRequest.to(HealthEndpoint.class, InfoEndpoint.class)).permitAll()
				.anyExchange().authenticated()
//				.and()
//				.httpBasic()
//				.and()
//				.formLogin()
				.and()
//				.addFilterAt()
				.oauth2Login()
				.and()
				.exceptionHandling()
				// NOTE:
				// This configuration is needed to perform the auto-redirect to UAA for authentication.
				// Leaving this out will result in a default login page with option for formLogin() and link for UAA for oauth2Login()
//				.authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint("/oauth2/authorization/login-client"))
				.and()
				.build();
		// @formatter:on
	}

	@GetMapping("/")
	public String index(Model model,
						@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
						@AuthenticationPrincipal OAuth2User oauth2User) {
		model.addAttribute("userName", oauth2User.getName());
		model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName());
		model.addAttribute("userAttributes", oauth2User.getAttributes());
		return "index";
	}

	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}

}