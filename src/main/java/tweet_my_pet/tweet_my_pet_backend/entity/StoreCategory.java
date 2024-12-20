package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "store_category")
public class StoreCategory {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "store_category_id", nullable = false)
    private Integer storeCategoryId;

    @Column(name = "store_category_name", nullable = false, length = 45)
    private String storeCategoryName;

}