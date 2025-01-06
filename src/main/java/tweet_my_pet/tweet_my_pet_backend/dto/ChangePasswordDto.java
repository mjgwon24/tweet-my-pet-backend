package tweet_my_pet.tweet_my_pet_backend.dto;

import lombok.Getter;
import lombok.Setter;
@Getter @Setter
public class ChangePasswordDto {
    private String token;
    private String phoneNumber;
    private String password;
}