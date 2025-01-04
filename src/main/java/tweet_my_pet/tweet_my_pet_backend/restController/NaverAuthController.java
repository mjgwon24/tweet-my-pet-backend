package tweet_my_pet.tweet_my_pet_backend.restController;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import tweet_my_pet.tweet_my_pet_backend.dto.NaverUserInfoDto;
import tweet_my_pet.tweet_my_pet_backend.entity.User;
import tweet_my_pet.tweet_my_pet_backend.service.NaverService;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/auth/naver")
public class NaverAuthController {

    @Value("${naver.client-id}")
    private String clientId;

    @Value("${naver.client-secret}")
    private String clientSecret;

    private final NaverService naverService;

    public NaverAuthController(NaverService naverService) {
        this.naverService = naverService;
    }

    @PostMapping("/callback")
    public ResponseEntity<Map<String, String>> handleNaverCallback(@RequestBody NaverUserInfoDto userInfo) {
        log.info("나는 임석진");
        String authorizationCode = userInfo.getCode();
        String state = userInfo.getState();

        // 네이버 API로부터 액세스 토큰 및 리프레시 토큰 가져오기
        String tokenUrl = "https://nid.naver.com/oauth2.0/token";
        RestTemplate restTemplate = new RestTemplate();

        try {
            // 파라미터 설정
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "authorization_code");
            params.add("client_id", clientId);
            params.add("client_secret", clientSecret);
            params.add("code", authorizationCode);
            params.add("state", state);

            // 토큰 요청
            ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(tokenUrl, params, Map.class);
            Map<String, Object> tokenData = tokenResponse.getBody();

            if (tokenData != null && tokenData.containsKey("access_token")) {
                String accessToken = (String) tokenData.get("access_token");
                String refreshToken = (String) tokenData.get("refresh_token");

                // 네이버 API로부터 사용자 정보 가져오기
                Map<String, Object> userResponse = naverService.getUserInfoFromNaver(accessToken);
                Map<String, Object> response = (Map<String, Object>) userResponse.get("response");

                String email = (String) response.get("email");
                String name = (String) response.get("name");
                String mobile = (String) response.get("mobile");

                // 사용자 정보 저장 및 업데이트
                User user = naverService.registerOrLoginUser(email, name, mobile, accessToken, refreshToken);

                // JSON 응답 생성
                Map<String, String> tokenResponses = new HashMap<>();
                tokenResponses.put("authToken", accessToken);
                tokenResponses.put("refreshToken", refreshToken);

                return ResponseEntity.ok(tokenResponses);

            } else {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "토큰 요청 실패");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }
        } catch (Exception e) {
            e.printStackTrace();
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "네이버 로그인 처리 실패");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }
}
