package tweet_my_pet.tweet_my_pet_backend.entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Enumerated;
import jakarta.persistence.EnumType;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.util.Date;

@Getter
@Setter
@Entity
@Table(name = "pet")
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Pet {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // IDENTITY 전략 사용
    @Column(name = "pet_id", nullable = false)
    private Long petId;

    @Column(name = "pet_name", nullable = false, length = 45)
    private String petName;

    @Column(name = "pet_birth", nullable = false)
    private Date petBirth;

    @Enumerated(EnumType.STRING)
    @Column(name = "pet_gender", nullable = false)
    private PetGender petGender;

    public enum PetGender {
        male, female
    }

    @Column(name = "pet_breed", length = 45)
    private String petBreed;
}
