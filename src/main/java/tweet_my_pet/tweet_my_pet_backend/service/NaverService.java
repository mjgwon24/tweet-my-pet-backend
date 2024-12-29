package tweet_my_pet.tweet_my_pet_backend.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import tweet_my_pet.tweet_my_pet_backend.entity.NaverApiUserLogin;
import tweet_my_pet.tweet_my_pet_backend.entity.User;
import tweet_my_pet.tweet_my_pet_backend.repository.NaverApiUserLoginRepository;
import tweet_my_pet.tweet_my_pet_backend.repository.UsersRepository;

import java.util.Map;

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

        return (Map<String, Object>) response.getBody().get("response");
    }

    public User registerOrLoginUser(Map<String, Object> userInfo, String accessToken, String refreshToken) {
        // 사용자 정보 파싱
        String userName = (String) userInfo.get("name");
        String userEmail = (String) userInfo.get("email");

        // User 엔티티 저장 또는 기존 사용자 조회
        User user = usersRepository.findByUserEmail(userEmail)
                .orElseGet(() -> usersRepository.save(
                        User.builder()
                                .userName(userName)
                                .userEmail(userEmail)
                                .build()
                ));

        // NaverApiUserLogin 엔티티 저장
        NaverApiUserLogin naverApiUserLogin = naverApiUserLoginRepository.findByUser(user)
                .orElseGet(() -> naverApiUserLoginRepository.save(
                        NaverApiUserLogin.builder()
                                .naverApiUserName(userName)
                                .naverApiAccessToken(accessToken)
                                .naverApiRefreshToken(refreshToken)
                                .user(user)
                                .build()
                ));

        return user;
    }




    public String refreshAccessToken(String refreshToken) {
        String tokenUrl = UriComponentsBuilder.fromHttpUrl("https://nid.naver.com/oauth2.0/token")
                .queryParam("grant_type", "refresh_token")
                .queryParam("client_id", clientId)
                .queryParam("client_secret", clientSecret)
                .queryParam("refresh_token", refreshToken)
                .toUriString();

        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, null, Map.class);
        Map<String, String> tokenData = (Map<String, String>) response.getBody();

        return tokenData.get("access_token");
    }
}
