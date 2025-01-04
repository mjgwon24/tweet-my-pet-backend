package tweet_my_pet.tweet_my_pet_backend.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class NaverUserInfoDto {
    private String name;
    private String email;
    private String mobile;
    private String state;
    private String code;
}
