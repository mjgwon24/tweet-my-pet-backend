package tweet_my_pet.tweet_my_pet_backend.restController;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.UUID;

@RestController
@RequestMapping("/auth/naver")
public class NaverRestController {

    @Value("${naver.client_id}")
    private String clientId;

    @Value("${naver.redirect_uri}")
    private String redirectUri;

    @GetMapping("/login")
    public ResponseEntity<?> initiateLogin(HttpServletRequest request) {
        String state = UUID.randomUUID().toString();
        request.getSession().setAttribute("naver_state", state);
        String redirectUrl = "https://nid.naver.com/oauth2.0/authorize?client_id=YOUR_CLIENT_ID"
                + "&response_type=code"
                + "&redirect_uri=YOUR_REDIRECT_URI"
                + "&state=" + state;
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(redirectUrl)).build();
    }
}
