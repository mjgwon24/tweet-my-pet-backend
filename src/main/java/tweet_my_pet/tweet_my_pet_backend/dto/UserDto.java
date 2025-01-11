package tweet_my_pet.tweet_my_pet_backend.dto;

import jakarta.persistence.*;
import lombok.Builder;
import tweet_my_pet.tweet_my_pet_backend.entity.Pet;
import tweet_my_pet.tweet_my_pet_backend.entity.User;
import tweet_my_pet.tweet_my_pet_backend.entity.room.Reservation;

import java.util.ArrayList;
import java.util.List;
import lombok.*;

@Getter @Setter
public class UserDto {
    @Builder
    public record FetchUserResponse(
            Long userId,
            PetDto pet,
            String userName,
            String userPhoneNumber,
            String userEmail,
            List<Reservation> reservations,
            String loginType
    ) {}
}
