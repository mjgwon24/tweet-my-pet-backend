package tweet_my_pet.tweet_my_pet_backend.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.geo.Point;
import tweet_my_pet.tweet_my_pet_backend.entity.enums.StoreCategory;

/**
 * 인증 코드 검증 요청 DTO
 */
@Getter @Setter
public class AuthCodeVerificationRequestDto {
    private String phoneNumber;
    private String authCode;
    @Builder
    public record CreateIdAuthCodeVerificationRequest(
            String phoneNumber,
            String userName
    ) {}
    @Builder
    public record CreatePasswordAuthCodeVerificationRequest(
            String phoneNumber,
            String userName,
            String userEmail
    ) {}
    @Builder
    public record AuthCodeVerificationRequest(
            String phoneNumber,
            String userName,
            String authCode
    ) { }
}
