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
@Table(name = "company_category")
public class CompanyCategory {
    @Id
    @Column(name = "company_category_id", nullable = false)
    private Integer companyCategoryId;

    @Column(name = "company_category_name", nullable = false, length = 45)
    private String companyCategoryName;

}