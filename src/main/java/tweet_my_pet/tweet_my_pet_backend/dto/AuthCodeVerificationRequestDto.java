package tweet_my_pet.tweet_my_pet_backend.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * 인증 코드 검증 요청 DTO
 */
@Getter @Setter
public class AuthCodeVerificationRequestDto {
    private String phoneNumber;
    private String authCode;
}
