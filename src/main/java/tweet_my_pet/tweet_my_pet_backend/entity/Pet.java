package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "pet", schema = "tweet_my_pet")
public class Pet {
    @Id
    @Column(name = "pet_id", nullable = false)
    private Long id;

    @Column(name = "pet_name", nullable = false, length = 45)
    private String petName;

/*
 TODO [Reverse Engineering] create field to map the 'pet_size' column
 Available actions: Define target Java type | Uncomment as is | Remove column mapping
    @Column(name = "pet_size", columnDefinition = "pet_size_type not null")
    private Object petSize;
*/
/*
 TODO [Reverse Engineering] create field to map the 'pet_gender' column
 Available actions: Define target Java type | Uncomment as is | Remove column mapping
    @Column(name = "pet_gender", columnDefinition = "gender_type not null")
    private Object petGender;
*/
}