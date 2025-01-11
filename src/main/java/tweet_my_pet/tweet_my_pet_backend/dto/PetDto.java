package tweet_my_pet.tweet_my_pet_backend.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import tweet_my_pet.tweet_my_pet_backend.entity.enums.PetSizeType;
import tweet_my_pet.tweet_my_pet_backend.entity.Pet.PetGender;

import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PetDto {

    private Long petId;
    private String petName;
    private Date petBirth;
    private PetGender petGender;
    private String petBreed;
    private PetSizeType petSize;
}
