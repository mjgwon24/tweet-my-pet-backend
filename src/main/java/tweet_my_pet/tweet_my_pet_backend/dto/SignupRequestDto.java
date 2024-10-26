package tweet_my_pet.tweet_my_pet_backend.dto;

import lombok.*;

/**
 * 회원가입 요청 DTO
 */
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignupRequestDto {
    private String loginId;
    private String password;
    private String name;
    private String phoneNumber;
}
