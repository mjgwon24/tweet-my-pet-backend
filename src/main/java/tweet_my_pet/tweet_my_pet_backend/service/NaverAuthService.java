package tweet_my_pet.tweet_my_pet_backend.service;

import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import tweet_my_pet.tweet_my_pet_backend.entity.NaverApiUserLogin;
import tweet_my_pet.tweet_my_pet_backend.entity.User;
import tweet_my_pet.tweet_my_pet_backend.repository.NaverApiUserLoginRepository;
import tweet_my_pet.tweet_my_pet_backend.repository.UsersRepository;

import java.util.HashMap;
import java.util.Map;

@Service
public class NaverAuthService {

    private final String CLIENT_ID = "네이버_클라이언트_ID";
    private final String CLIENT_SECRET = "네이버_클라이언트_SECRET";

    private final RestTemplate restTemplate;
    private final UsersRepository usersRepository;
    private final NaverApiUserLoginRepository naverApiUserLoginRepository;

    public NaverAuthService(RestTemplate restTemplate, UsersRepository usersRepository, NaverApiUserLoginRepository naverApiUserLoginRepository) {
        this.restTemplate = restTemplate;
        this.usersRepository = usersRepository;
        this.naverApiUserLoginRepository = naverApiUserLoginRepository;
    }

    public Map<String, Object> processNaverLogin(String code, String state) {
        String tokenUrl = "https://nid.naver.com/oauth2.0/token";
        String userInfoUrl = "https://openapi.naver.com/v1/nid/me";

        // 1. Access Token 요청
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", CLIENT_ID);
        params.add("client_secret", CLIENT_SECRET);
        params.add("code", code);
        params.add("state", state);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

        Map<String, Object> tokenData = response.getBody();
        String accessToken = (String) tokenData.get("access_token");
        String refreshToken = (String) tokenData.get("refresh_token");

        // 2. 사용자 정보 요청
        headers.clear();
        headers.add("Authorization", "Bearer " + accessToken);
        HttpEntity<Void> userInfoRequest = new HttpEntity<>(headers);
        ResponseEntity<Map> userInfoResponse = restTemplate.exchange(userInfoUrl, HttpMethod.GET, userInfoRequest, Map.class);

        Map<String, Object> userInfo = (Map<String, Object>) userInfoResponse.getBody().get("response");

        // 3. 사용자 정보와 토큰 저장
        saveUserAndTokens(userInfo, accessToken, refreshToken);

        return userInfo; // 프론트로 반환
    }

    private void saveUserAndTokens(Map<String, Object> userInfo, String accessToken, String refreshToken) {
        // 사용자 정보
        String userName = (String) userInfo.get("name");
        String userEmail = (String) userInfo.get("email");

        // User 엔티티 저장 또는 조회
        User user = usersRepository.findByUserEmail(userEmail).orElseGet(() ->
                usersRepository.save(User.builder()
                        .userName(userName)
                        .userEmail(userEmail)
                        .build())
        );

        // NaverApiUserLogin 엔티티 저장 또는 업데이트
        naverApiUserLoginRepository.findByUser(user).orElseGet(() ->
                naverApiUserLoginRepository.save(NaverApiUserLogin.builder()
                        .naverApiUserName(userName)
                        .naverApiAccessToken(accessToken)
                        .naverApiRefreshToken(refreshToken)
                        .user(user)
                        .build())
        );
    }
}
