package tweet_my_pet.tweet_my_pet_backend.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.*;

/**
 * 회원가입 요청 DTO
 */
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignupRequestDto {
    // @NotBlank
    private String loginId;
    @Pattern(regexp = "^(?=.*[a-zA-Z])(?=.*[0-9])(?=.*[!@#$%^&*()_+]).{8,}$",
            message = "비밀번호는 문자, 숫자, 특수문자를 포함한 8자 이상이어야 합니다.")
    private String password;
    // @NotBlank
    private String name;
    // @NotBlank
    private String email;
    // @NotBlank
    private String phoneNumber;
}
