package tweet_my_pet.tweet_my_pet_backend.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import tweet_my_pet.tweet_my_pet_backend.entity.NaverApiUserLogin;
import tweet_my_pet.tweet_my_pet_backend.entity.User;
import tweet_my_pet.tweet_my_pet_backend.repository.NaverApiUserLoginRepository;
import tweet_my_pet.tweet_my_pet_backend.repository.UsersRepository;

import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
public class NaverService {

    @Value("${naver.client_id}")
    private String clientId;

    @Value("${naver.client_secret}")
    private String clientSecret;

    private final UsersRepository usersRepository;
    private final NaverApiUserLoginRepository naverApiUserLoginRepository;
    private final RestTemplate restTemplate;

    public NaverService(UsersRepository usersRepository, NaverApiUserLoginRepository naverApiUserLoginRepository, RestTemplate restTemplate) {
        this.usersRepository = usersRepository;
        this.naverApiUserLoginRepository = naverApiUserLoginRepository;
        this.restTemplate = restTemplate;
    }

    public Map<String, Object> getUserInfo(String accessToken) {
        String userInfoUrl = "https://openapi.naver.com/v1/nid/me";
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        ResponseEntity<Map> response = restTemplate.exchange(
                userInfoUrl,
                org.springframework.http.HttpMethod.GET,
                new HttpEntity<>(headers),
                Map.class
        );

        log.info("네이버 사용자 정보 API 응답: {}", response.getBody());

        return (Map<String, Object>) response.getBody().get("response");
    }

    public User registerOrLoginUser(Map<String, Object> userInfo, String accessToken, String refreshToken) {
        log.info("발급된 Access Token: {}", accessToken);
        log.info("발급된 Refresh Token: {}", refreshToken);

        log.info("네이버 사용자 정보: {}", userInfo);

        // 사용자 정보 파싱
        String userName = (String) userInfo.get("name");
        String userEmail = (String) userInfo.get("email");
        String userPhoneNumber = (String) userInfo.getOrDefault("phone_number", "N/A");

        // User 엔티티 저장 또는 기존 사용자 조회
        User user = usersRepository.findByUserEmail(userEmail)
                .orElseGet(() -> usersRepository.save(
                        User.builder()
                                .userName(userName)
                                .userEmail(userEmail)
                                .userPhoneNumber(userPhoneNumber)
                                .build()
                ));

        // NaverApiUserLogin 엔티티 저장
        naverApiUserLoginRepository.findByUser(user)
                .orElseGet(() -> naverApiUserLoginRepository.save(
                        NaverApiUserLogin.builder()
                                .naverApiUserName(userName)
                                .naverApiAccessToken(accessToken)
                                .naverApiRefreshToken(refreshToken)
                                .user(user)
                                .build()
                ));

        log.info("NaverApiUserLogin 저장 완료: {}", naverApiUserLoginRepository);
        return user;
    }
}
