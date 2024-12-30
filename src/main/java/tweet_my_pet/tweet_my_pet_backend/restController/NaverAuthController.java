package tweet_my_pet.tweet_my_pet_backend.restController;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import tweet_my_pet.tweet_my_pet_backend.entity.User;
import tweet_my_pet.tweet_my_pet_backend.service.NaverService;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/auth/naver")
public class NaverAuthController {

    @Value("${naver.client_id}")
    private String clientId;

    @Value("${naver.client_secret}")
    private String clientSecret;

    private final RestTemplate restTemplate;
    private final NaverService naverService;

    public NaverAuthController(RestTemplate restTemplate, NaverService naverService) {
        this.restTemplate = restTemplate;
        this.naverService = naverService;
    }

    @PostMapping("/callback")
    public ResponseEntity<?> handleNaverCallback(@RequestBody Map<String, String> requestData) {
        String code = requestData.get("code");
        String state = requestData.get("state");

        if (code == null || state == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid request data");
        }

        try {
            // 네이버 토큰 요청
            String tokenUrl = UriComponentsBuilder.fromHttpUrl("https://nid.naver.com/oauth2.0/token")
                    .queryParam("grant_type", "authorization_code")
                    .queryParam("client_id", clientId)
                    .queryParam("client_secret", clientSecret)
                    .queryParam("code", code)
                    .queryParam("state", state)
                    .toUriString();

            ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(tokenUrl, null, Map.class);
            Map<String, String> tokenData = (Map<String, String>) tokenResponse.getBody();

            log.info("네이버 토큰 발급 응답: {}", tokenData);

            String accessToken = tokenData.get("access_token");
            String refreshToken = tokenData.get("refresh_token");


            // 사용자 정보 요청 및 DB 저장
            Map<String, Object> userInfo = naverService.getUserInfo(accessToken);
            User user = naverService.registerOrLoginUser(userInfo, accessToken, refreshToken);

            return ResponseEntity.ok(Map.of(
                    "authToken", accessToken,  // 또는 다른 토큰 값
                    "refreshToken", refreshToken
            ));
        } catch (Exception e) {
            log.error("네이버 로그인 처리 실패: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to process Naver login");
        }
    }
}
