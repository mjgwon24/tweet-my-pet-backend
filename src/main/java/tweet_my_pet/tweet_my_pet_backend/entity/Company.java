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
@Table(name = "company", schema = "tweet_my_pet")
public class Company {
    @Id
    @Column(name = "company_id", nullable = false)
    private Long id;

    @Column(name = "company_name", nullable = false, length = 45)
    private String companyName;

    @Column(name = "company_tel", nullable = false, length = 45)
    private String companyTel;

    @Column(name = "company_location", nullable = false)
    private String companyLocation;

    @Column(name = "company_president_name", nullable = false, length = 45)
    private String companyPresidentName;

}