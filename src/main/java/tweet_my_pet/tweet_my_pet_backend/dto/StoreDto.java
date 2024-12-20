package tweet_my_pet.tweet_my_pet_backend.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class StoreDto {
    private String name;
    private String tel;
    private String location;
    private String presidentName;
    private double latitude;
    private double longitude;
}
