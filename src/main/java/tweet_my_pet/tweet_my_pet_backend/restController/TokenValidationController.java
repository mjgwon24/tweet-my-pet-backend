package tweet_my_pet.tweet_my_pet_backend.restController;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tweet_my_pet.tweet_my_pet_backend.service.TokenValidationService;

@RestController
@RequestMapping("/auth")
public class TokenValidationController {

    private final TokenValidationService tokenValidationService;

    public TokenValidationController(TokenValidationService tokenValidationService) {
        this.tokenValidationService = tokenValidationService;
    }

    @GetMapping("/validate-token")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String token) {
        boolean isValid = tokenValidationService.validateToken(token.replace("Bearer ", ""));

        if (isValid) {
            return ResponseEntity.ok().body("Token is valid");
        } else {
            return ResponseEntity.status(401).body("Invalid or expired token");
        }
    }
}
