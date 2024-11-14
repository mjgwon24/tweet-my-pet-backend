package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "pet", schema = "tweet_my_pet")
public class Pet {
    @Id
    @Column(name = "pet_id", nullable = false)
    private Long petId;

    @Column(name = "pet_name", nullable = false, length = 45)
    private String petName;

    @Enumerated(EnumType.STRING)
    @Column(name = "pet_size", columnDefinition = "pet_size_type not null")
    private PetSize petSize;

    public enum PetSize {
        대, 중, 소
    }

    @Enumerated(EnumType.STRING)
    @Column(name = "pet_gender", columnDefinition = "gender_type not null")
    private Gender petGender;

    public enum Gender {
        암, 수
    }
}