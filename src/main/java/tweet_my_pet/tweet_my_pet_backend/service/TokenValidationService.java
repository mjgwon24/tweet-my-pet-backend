package tweet_my_pet.tweet_my_pet_backend.service;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class TokenValidationService {

    private final RestTemplate restTemplate;

    public TokenValidationService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public boolean validateToken(String accessToken) {
        String validationUrl = "https://openapi.naver.com/v1/nid/me";

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);

        try {
            HttpEntity<Void> request = new HttpEntity<>(headers);
            ResponseEntity<String> response = restTemplate.postForEntity(validationUrl, request, String.class);

            return response.getStatusCode().is2xxSuccessful();
        } catch (Exception e) {
            return false;
        }
    }
}
