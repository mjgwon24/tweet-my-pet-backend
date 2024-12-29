package tweet_my_pet.tweet_my_pet_backend.restController;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import tweet_my_pet.tweet_my_pet_backend.entity.User;
import tweet_my_pet.tweet_my_pet_backend.service.NaverService;

import java.util.Map;

@RestController
@RequestMapping("/auth/naver")
public class NaverRestController {

    @Value("${naver.client_id}")
    private String clientId;

    @Value("${naver.client_secret}")
    private String clientSecret;

    @Value("${naver.redirect_uri}")
    private String redirectUri;

    private final RestTemplate restTemplate;
    private final NaverService naverService;

    public NaverRestController(RestTemplate restTemplate, NaverService naverService) {
        this.restTemplate = restTemplate;
        this.naverService = naverService;
    }

    // 기존 GetMapping("/login") 유지
    @GetMapping("/login")
    public ResponseEntity<?> naverLogin() {
        String state = "custom_state";
        String url = UriComponentsBuilder.fromHttpUrl("https://nid.naver.com/oauth2.0/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("state", state)
                .toUriString();
        return ResponseEntity.status(302).header("Location", url).build();
    }

    // 기존 GetMapping("/callback") 유지
    @GetMapping("/callback")
    public ResponseEntity<?> naverCallback(@RequestParam String code, @RequestParam String state) {
        String tokenUrl = UriComponentsBuilder.fromHttpUrl("https://nid.naver.com/oauth2.0/token")
                .queryParam("grant_type", "authorization_code")
                .queryParam("client_id", clientId)
                .queryParam("client_secret", clientSecret)
                .queryParam("code", code)
                .queryParam("state", state)
                .toUriString();

        ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(tokenUrl, null, Map.class);
        Map<String, String> tokenData = (Map<String, String>) tokenResponse.getBody();

        String accessToken = tokenData.get("access_token");
        String refreshToken = tokenData.get("refresh_token");

        Map<String, Object> userInfo = naverService.getUserInfo(accessToken);
        User user = naverService.registerOrLoginUser(userInfo, accessToken, refreshToken);

        return ResponseEntity.ok(user);
    }

    // 새롭게 추가된 PostMapping("/callback")
    @PostMapping("/callback")
    public ResponseEntity<?> handleNaverCallback(@RequestBody Map<String, String> requestData) {
        // 입력 데이터 검증
        String code = requestData.get("code");
        String state = requestData.get("state");

        if (code == null || state == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid request data");
        }

        // 네이버 인증 처리 (예: 토큰 요청 로직)
        try {
            String tokenUrl = UriComponentsBuilder.fromHttpUrl("https://nid.naver.com/oauth2.0/token")
                    .queryParam("grant_type", "authorization_code")
                    .queryParam("client_id", clientId)
                    .queryParam("client_secret", clientSecret)
                    .queryParam("code", code)
                    .queryParam("state", state)
                    .toUriString();

            ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(tokenUrl, null, Map.class);
            Map<String, String> tokenData = (Map<String, String>) tokenResponse.getBody();

            String accessToken = tokenData.get("access_token");
            String refreshToken = tokenData.get("refresh_token");

            Map<String, Object> userInfo = naverService.getUserInfo(accessToken);
            User user = naverService.registerOrLoginUser(userInfo, accessToken, refreshToken);

            return ResponseEntity.ok(user);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to process Naver login");
        }
    }
}
