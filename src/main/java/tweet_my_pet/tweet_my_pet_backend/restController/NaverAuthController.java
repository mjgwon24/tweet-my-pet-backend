package tweet_my_pet.tweet_my_pet_backend.restController;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tweet_my_pet.tweet_my_pet_backend.service.NaverAuthService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth/naver")
public class NaverAuthController {

    @Autowired
    private NaverAuthService naverAuthService;


}
