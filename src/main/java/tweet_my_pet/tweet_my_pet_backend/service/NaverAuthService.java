package tweet_my_pet.tweet_my_pet_backend.service;

import org.json.JSONObject;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import java.util.HashMap;
import java.util.Map;

@Service
public class NaverAuthService {

    private final String CLIENT_ID = "네이버_클라이언트_ID";
    private final String CLIENT_SECRET = "네이버_클라이언트_SECRET";

    public Map<String, Object> processNaverLogin(String code, String state) {
        String tokenUrl = "https://nid.naver.com/oauth2.0/token";
        String userInfoUrl = "https://openapi.naver.com/v1/nid/me";

        // 1. Access Token 요청
        RestTemplate restTemplate = new RestTemplate();
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

        // 2. 사용자 정보 요청
        headers.clear();
        headers.add("Authorization", "Bearer " + accessToken);
        HttpEntity<Void> userInfoRequest = new HttpEntity<>(headers);
        ResponseEntity<Map> userInfoResponse = restTemplate.exchange(userInfoUrl, HttpMethod.GET, userInfoRequest, Map.class);

        return userInfoResponse.getBody();
    }
}

