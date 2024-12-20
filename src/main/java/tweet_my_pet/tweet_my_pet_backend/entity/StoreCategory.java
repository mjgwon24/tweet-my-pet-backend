package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "company_category")
public class StoreCategory {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "company_category_id", nullable = false)
    private Integer companyCategoryId;

    @Column(name = "company_category_name", nullable = false, length = 45)
    private String companyCategoryName;

}