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

    @Enumerated(EnumType.STRING) // Java Enum을 String으로 매핑
    @Column(name = "pet_size", nullable = false)
    private PetSizeType petSize;
}
